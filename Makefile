
test-cov: coverage coveralls codeclimate

coverage:
	npx nyc mocha

coveralls: coverage
	npx nyc report --reporter=text-lcov \
		 | npx coveralls --exclude tmp


# # note a CODECLIMATE_REPO_TOKEN must be specified as an environment variable.
codeclimate: coverage
	echo nothing
#	codeclimate-test-reporter < ./coverage/lcov.info

