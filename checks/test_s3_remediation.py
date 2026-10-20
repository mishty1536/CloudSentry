import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError

from s3_remediation import PROTECTED_BUCKET_NAME, remediate_s3_default_encryption


def aws_error(code, operation):
    return ClientError({"Error": {"Code": code, "Message": "mocked failure"}}, operation)


def sse_s3_response():
    return {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
            }]
        }
    }


class S3EncryptionRemediationTests(unittest.TestCase):
    bucket = "cloudsentry-remediation-test-2026"

    def test_missing_configuration_is_set_and_reread_as_aes256(self):
        s3 = Mock()
        s3.get_bucket_encryption.side_effect = [
            aws_error("ServerSideEncryptionConfigurationNotFoundError", "GetBucketEncryption"),
            sse_s3_response(),
        ]

        result = remediate_s3_default_encryption(
            s3, self.bucket, allowed_bucket_name=self.bucket
        )

        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["success"])
        s3.put_bucket_encryption.assert_called_once_with(
            Bucket=self.bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
                }]
            },
        )
        self.assertEqual(s3.get_bucket_encryption.call_count, 2)

    def test_write_is_not_reported_successful_when_reread_does_not_confirm_aes256(self):
        s3 = Mock()
        s3.get_bucket_encryption.side_effect = [
            aws_error("ServerSideEncryptionConfigurationNotFoundError", "GetBucketEncryption"),
            {"ServerSideEncryptionConfiguration": {"Rules": [{
                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}
            }]}},
        ]

        result = remediate_s3_default_encryption(
            s3, self.bucket, allowed_bucket_name=self.bucket
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "verification_failed")
        self.assertIn("unverified", result["message"])

    def test_access_denied_during_precheck_does_not_write_or_claim_success(self):
        s3 = Mock()
        s3.get_bucket_encryption.side_effect = aws_error("AccessDenied", "GetBucketEncryption")

        result = remediate_s3_default_encryption(
            s3, self.bucket, allowed_bucket_name=self.bucket
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "access_denied")
        s3.put_bucket_encryption.assert_not_called()

    def test_access_denied_on_write_is_reported_without_success(self):
        s3 = Mock()
        s3.get_bucket_encryption.side_effect = aws_error(
            "ServerSideEncryptionConfigurationNotFoundError", "GetBucketEncryption"
        )
        s3.put_bucket_encryption.side_effect = aws_error("AccessDenied", "PutBucketEncryption")

        result = remediate_s3_default_encryption(
            s3, self.bucket, allowed_bucket_name=self.bucket
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "access_denied")

    def test_missing_bucket_is_reported_without_a_write(self):
        s3 = Mock()
        s3.get_bucket_encryption.side_effect = aws_error("NoSuchBucket", "GetBucketEncryption")

        result = remediate_s3_default_encryption(
            s3, self.bucket, allowed_bucket_name=self.bucket
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "bucket_not_found")
        s3.put_bucket_encryption.assert_not_called()

    def test_api_error_during_write_is_not_reported_as_success(self):
        s3 = Mock()
        s3.get_bucket_encryption.side_effect = aws_error(
            "ServerSideEncryptionConfigurationNotFoundError", "GetBucketEncryption"
        )
        s3.put_bucket_encryption.side_effect = aws_error("InternalError", "PutBucketEncryption")

        result = remediate_s3_default_encryption(
            s3, self.bucket, allowed_bucket_name=self.bucket
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "api_error")

    def test_access_denied_during_verification_does_not_claim_success(self):
        s3 = Mock()
        s3.get_bucket_encryption.side_effect = [
            aws_error("ServerSideEncryptionConfigurationNotFoundError", "GetBucketEncryption"),
            aws_error("AccessDenied", "GetBucketEncryption"),
        ]

        result = remediate_s3_default_encryption(
            s3, self.bucket, allowed_bucket_name=self.bucket
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "verification_access_denied")

    def test_existing_cloudsentry_bucket_is_hard_denied_before_any_api_call(self):
        s3 = Mock()

        result = remediate_s3_default_encryption(
            s3,
            PROTECTED_BUCKET_NAME,
            allowed_bucket_name=PROTECTED_BUCKET_NAME,
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "protected_bucket")
        s3.get_bucket_encryption.assert_not_called()
        s3.put_bucket_encryption.assert_not_called()

    def test_bucket_outside_allowlist_cannot_be_written(self):
        s3 = Mock()

        result = remediate_s3_default_encryption(
            s3, "other-bucket", allowed_bucket_name=self.bucket
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "not_allowlisted")
        s3.get_bucket_encryption.assert_not_called()
        s3.put_bucket_encryption.assert_not_called()

    def test_existing_non_aes256_configuration_is_not_replaced(self):
        s3 = Mock()
        s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {"Rules": [{
                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}
            }]}
        }

        result = remediate_s3_default_encryption(
            s3, self.bucket, allowed_bucket_name=self.bucket
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "existing_configuration")
        s3.put_bucket_encryption.assert_not_called()

    def test_already_configured_aes256_does_not_write(self):
        s3 = Mock()
        s3.get_bucket_encryption.return_value = sse_s3_response()

        result = remediate_s3_default_encryption(
            s3, self.bucket, allowed_bucket_name=self.bucket
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "already_configured")
        s3.put_bucket_encryption.assert_not_called()


if __name__ == "__main__":
    unittest.main()
