# Data source for current AWS account
data "aws_caller_identity" "current" {}

# SSM Document for applying High Priority DSC configuration
resource "aws_ssm_document" "high_priority_dsc" {
  count           = local.deploy_high_priority ? 1 : 0
  name            = "ACSC-HighPriority-DSC"
  document_type   = "Command"
  document_format = "JSON"
  tags            = var.tags

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Apply ACSC High Priority Windows Hardening DSC Configuration"
    parameters = {
      s3BucketName = {
        type        = "String"
        description = "S3 bucket containing DSC package"
        default     = var.s3_bucket_name
      }
      s3Key = {
        type        = "String"
        description = "S3 key for DSC package"
        default     = "packages/ACSCHighPriorityHardening.zip"
      }
    }
    mainSteps = [
      {
        action = "aws:runPowerShellScript"
        name   = "downloadAndApplyDSC"
        inputs = {
          runCommand = [
            "$ErrorActionPreference = 'Stop'",
            "Write-Output 'Downloading DSC package from S3...'",
            "$tempDir = Join-Path $env:TEMP 'ACSC-DSC'",
            "New-Item -ItemType Directory -Path $tempDir -Force | Out-Null",
            "$zipPath = Join-Path $tempDir 'ACSCHighPriorityHardening.zip'",
            "Read-S3Object -BucketName '{{ s3BucketName }}' -Key '{{ s3Key }}' -File $zipPath",
            "Write-Output 'Extracting DSC package...'",
            "$extractPath = Join-Path $tempDir 'extracted'",
            "Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force",
            "Write-Output 'Applying DSC configuration...'",
            "$mofFile = Get-ChildItem -Path $extractPath -Filter '*.mof' -Recurse | Select-Object -First 1",
            "if ($mofFile) {",
            "    Start-DscConfiguration -Path $mofFile.DirectoryName -Wait -Verbose -Force",
            "    Write-Output 'DSC configuration applied successfully'",
            "} else {",
            "    throw 'No MOF file found in package'",
            "}",
            "Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue"
          ]
        }
      }
    ]
  })
}

# SSM Document for applying Medium Priority DSC configuration
resource "aws_ssm_document" "medium_priority_dsc" {
  count           = local.deploy_medium_priority ? 1 : 0
  name            = "ACSC-MediumPriority-DSC"
  document_type   = "Command"
  document_format = "JSON"
  tags            = var.tags

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Apply ACSC Medium Priority Windows Hardening DSC Configuration"
    parameters = {
      s3BucketName = {
        type        = "String"
        description = "S3 bucket containing DSC package"
        default     = var.s3_bucket_name
      }
      s3Key = {
        type        = "String"
        description = "S3 key for DSC package"
        default     = "packages/ACSCMediumPriorityHardening.zip"
      }
    }
    mainSteps = [
      {
        action = "aws:runPowerShellScript"
        name   = "downloadAndApplyDSC"
        inputs = {
          runCommand = [
            "$ErrorActionPreference = 'Stop'",
            "Write-Output 'Downloading DSC package from S3...'",
            "$tempDir = Join-Path $env:TEMP 'ACSC-DSC'",
            "New-Item -ItemType Directory -Path $tempDir -Force | Out-Null",
            "$zipPath = Join-Path $tempDir 'ACSCMediumPriorityHardening.zip'",
            "Read-S3Object -BucketName '{{ s3BucketName }}' -Key '{{ s3Key }}' -File $zipPath",
            "Write-Output 'Extracting DSC package...'",
            "$extractPath = Join-Path $tempDir 'extracted'",
            "Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force",
            "Write-Output 'Applying DSC configuration...'",
            "$mofFile = Get-ChildItem -Path $extractPath -Filter '*.mof' -Recurse | Select-Object -First 1",
            "if ($mofFile) {",
            "    Start-DscConfiguration -Path $mofFile.DirectoryName -Wait -Verbose -Force",
            "    Write-Output 'DSC configuration applied successfully'",
            "} else {",
            "    throw 'No MOF file found in package'",
            "}",
            "Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue"
          ]
        }
      }
    ]
  })
}

# State Manager Association for High Priority configuration
resource "aws_ssm_association" "high_priority" {
  count               = local.deploy_high_priority ? 1 : 0
  name                = aws_ssm_document.high_priority_dsc[0].name
  schedule_expression = var.remediation_schedule

  targets {
    key    = "tag:${var.target_tag_key}"
    values = [var.target_tag_value]
  }

  output_location {
    s3_bucket_name = aws_s3_bucket.acsc.id
    s3_key_prefix  = "ssm-logs/high-priority"
  }

  compliance_severity = "HIGH"
}

# State Manager Association for Medium Priority configuration
resource "aws_ssm_association" "medium_priority" {
  count               = local.deploy_medium_priority ? 1 : 0
  name                = aws_ssm_document.medium_priority_dsc[0].name
  schedule_expression = var.remediation_schedule

  targets {
    key    = "tag:${var.target_tag_key}"
    values = [var.target_tag_value]
  }

  output_location {
    s3_bucket_name = aws_s3_bucket.acsc.id
    s3_key_prefix  = "ssm-logs/medium-priority"
  }

  compliance_severity = "MEDIUM"
}
