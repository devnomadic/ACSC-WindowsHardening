# IAM role for EC2 instances to access S3 and Systems Manager
resource "aws_iam_role" "ec2_ssm" {
  name = "ACSCHardeningEC2SSMRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# Attach AWS managed policy for Systems Manager
resource "aws_iam_role_policy_attachment" "ssm_managed_policy" {
  role       = aws_iam_role.ec2_ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Custom policy for S3 access to DSC packages
resource "aws_iam_role_policy" "s3_dsc_access" {
  name = "ACSCHardeningS3Access"
  role = aws_iam_role.ec2_ssm.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.acsc.arn,
          "${aws_s3_bucket.acsc.arn}/*"
        ]
      }
    ]
  })
}

# Instance profile for EC2 instances
resource "aws_iam_instance_profile" "ec2_ssm" {
  name = "ACSCHardeningEC2SSMProfile"
  role = aws_iam_role.ec2_ssm.name
  tags = var.tags
}
