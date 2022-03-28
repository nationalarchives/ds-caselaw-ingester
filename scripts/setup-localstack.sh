awslocal iam create-role \
  --role-name lambda-role \
  --assume-role-policy-document file://aws_examples/example_trust_policy.json

awslocal lambda create-function \
  --function-name te-lambda \
  --zip-file fileb://dist/lambda.zip \
  --handler lambda_function.handler \
  --runtime python3.9 \
  --role arn:aws:iam::000000000000:role/lambda-role

awslocal sns create-topic \
  --name judgments \
  --attributes consignment-reference=string,s3-folder-url=string,consignment-type=string,number-of-retries=number

awslocal sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:000000000000:judgments \
  --protocol lambda \
  --notification-endpoint arn:aws:lambda:us-east-1:000000000000:function:te-lambda

awslocal s3api create-bucket \
  --bucket te-editorial-out-int

awslocal s3 cp aws_examples/s3/te-editorial-out-int/TRE-TDR-2022-DNWR.tar.gz s3://te-editorial-out-int
