output "s3_bucket_name" {
  description = "Name of the S3 bucket containing DSC packages"
  value       = aws_s3_bucket.acsc.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.acsc.arn
}

output "s3_bucket_region" {
  description = "Region of the S3 bucket"
  value       = aws_s3_bucket.acsc.region
}

output "high_priority_package_s3_key" {
  description = "S3 key of the High Priority package"
  value       = local.deploy_high_priority ? aws_s3_object.high_priority_package[0].key : null
}

output "medium_priority_package_s3_key" {
  description = "S3 key of the Medium Priority package"
  value       = local.deploy_medium_priority ? aws_s3_object.medium_priority_package[0].key : null
}

output "high_priority_content_hash" {
  description = "SHA256 hash of the High Priority package"
  value       = local.deploy_high_priority ? local.high_priority_content_hash : null
}

output "medium_priority_content_hash" {
  description = "SHA256 hash of the Medium Priority package"
  value       = local.deploy_medium_priority ? local.medium_priority_content_hash : null
}

output "ssm_document_high_priority_name" {
  description = "Name of the SSM Document for High Priority configuration"
  value       = local.deploy_high_priority ? aws_ssm_document.high_priority_dsc[0].name : null
}

output "ssm_document_medium_priority_name" {
  description = "Name of the SSM Document for Medium Priority configuration"
  value       = local.deploy_medium_priority ? aws_ssm_document.medium_priority_dsc[0].name : null
}

output "ssm_association_high_priority_id" {
  description = "ID of the State Manager Association for High Priority"
  value       = local.deploy_high_priority ? aws_ssm_association.high_priority[0].id : null
}

output "ssm_association_medium_priority_id" {
  description = "ID of the State Manager Association for Medium Priority"
  value       = local.deploy_medium_priority ? aws_ssm_association.medium_priority[0].id : null
}

output "iam_role_name" {
  description = "Name of the IAM role for EC2 instances"
  value       = aws_iam_role.ec2_ssm.name
}

output "iam_role_arn" {
  description = "ARN of the IAM role for EC2 instances"
  value       = aws_iam_role.ec2_ssm.arn
}

output "iam_instance_profile_name" {
  description = "Name of the IAM instance profile for EC2 instances"
  value       = aws_iam_instance_profile.ec2_ssm.name
}

output "iam_instance_profile_arn" {
  description = "ARN of the IAM instance profile for EC2 instances"
  value       = aws_iam_instance_profile.ec2_ssm.arn
}

output "release_version" {
  description = "GitHub release version deployed"
  value       = local.release_data.tag_name
}

output "release_name" {
  description = "GitHub release name"
  value       = local.release_data.name
}

output "target_tag" {
  description = "Tag that EC2 instances must have to receive hardening"
  value       = "${var.target_tag_key}=${var.target_tag_value}"
}
