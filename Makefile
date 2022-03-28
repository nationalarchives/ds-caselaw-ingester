build:
	@mkdir -p dist
	@python3 -m pip install --target ./package -r requirements/base.txt
	@zip -r dist/lambda.zip package
	@zip -g dist/lambda.zip lambda_function.py
	@echo 'Built dist/lambda.zip'

setup:
	make build
	sh scripts/setup-localstack.sh


update:
	make build
	@sh scripts/update-lambda.sh

send-message:
	@awslocal sns publish --topic-arn arn:aws:sns:us-east-1:000000000000:judgments --message file://aws_examples/sns/parsed-judgment.json
