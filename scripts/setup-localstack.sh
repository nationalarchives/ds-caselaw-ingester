source .env

awslocal iam create-role \
  --role-name lambda-role \
  --assume-role-policy-document file://aws_examples/example_trust_policy.json

awslocal lambda create-function \
  --function-name te-lambda \
  --zip-file fileb://dist/lambda.zip \
  --handler ds-caselaw-ingester/lambda_function.handler \
  --runtime python3.9 \
  --environment "Variables={MARKLOGIC_HOST=$MARKLOGIC_HOST,MARKLOGIC_USER=$MARKLOGIC_USER,MARKLOGIC_PASSWORD=$MARKLOGIC_PASSWORD,AWS_BUCKET_NAME=$AWS_BUCKET_NAME,AWS_SECRET_KEY=$AWS_SECRET_KEY,AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID,AWS_ENDPOINT_URL=$AWS_ENDPOINT_URL,SQS_QUEUE_URL=$SQS_QUEUE_URL}" \
  --role arn:aws:iam::000000000000:role/lambda-role \

awslocal sns create-topic \
  --name judgments \
  --attributes consignment-reference=string,s3-folder-url=string,consignment-type=string,number-of-retries=number

awslocal sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:000000000000:judgments \
  --protocol lambda \
  --notification-endpoint arn:aws:lambda:us-east-1:000000000000:function:te-lambda

awslocal s3api create-bucket \
  --bucket te-editorial-out-int

awslocal s3api create-bucket \
  --bucket judgments-original-versions

awslocal s3 cp aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz s3://te-editorial-out-int

awslocal sqs create-queue --queue-name retry-queue
