package auth

import (
	"github.com/aws/aws-sdk-go/service/iam"
)

// AwsProvider provides authentication service with AWS service
type AwsProvider struct {
	iam *iam.IAM
}
