build:
	@mkdir -p dist
	@STATIC_DEPS=true python3 -m pip install -t package -r requirements/base.txt
	@rm dist/lambda.zip & 2>&1
	@cd package && zip -r ../dist/lambda.zip * && cd ..
	@zip -g dist/lambda.zip ds-caselaw-ingester/lambda_function.py
	@echo 'Built dist/lambda.zip'

setup:
	make build
	sh scripts/setup-localstack.sh

update:
	make build
	@sh scripts/update-lambda.sh

send-message:
	@awslocal sns publish --topic-arn arn:aws:sns:us-east-1:000000000000:judgments --message file://aws_examples/sns/parsed-judgment.json

delete-document:
	@curl --anyauth --user admin:admin -X DELETE -i http://localhost:8000/v1/documents\?database\=Judgments\&uri\=/ewca/civ/2022/111.xml

