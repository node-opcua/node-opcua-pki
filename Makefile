
test-cov: coverage coveralls codeclimate

coverage:
	nyc -x ./bin/ -x ./tmp -x ./lib/misc/install_pre* mocha

coveralls: coverage
	cat ./coverage/lcov.info | coveralls --exclude tmp

# note a CODECLIMATE_REPO_TOKEN must be specified as an environment variable.
codeclimate: coverage
	codeclimate-test-reporter < ./coverage/lcov.info

