# MiniStack for AWS services testing

The AWS related unit, integration and acceptance tests can run against
[MiniStack](https://github.com/ministackorg/ministack), a free and open-source local AWS emulator that
provides the Secrets Manager and KMS APIs used by Web3Signer. This is what GitHub CI uses, so no AWS
credentials are needed there.

Start MiniStack. It listens on port 4566 for all AWS services.

```bash
docker compose up
```

Use `CTRL-C` or run `docker compose down` from the same directory but from another shell instance.

Export the following environment variables before running the tests. MiniStack does not check
credentials, so any access key works.

```bash
export RW_AWS_ACCESS_KEY_ID=test
export RW_AWS_SECRET_ACCESS_KEY=test
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_ACCESS_KEY_ID_TEST2=test2
export AWS_SECRET_ACCESS_KEY_TEST2=test2
export AWS_REGION=us-east-2
export AWS_ENDPOINT_OVERRIDE=http://127.0.0.1:4566
```

To import above in IntelliJ IDEA Run configurations:
```
RW_AWS_ACCESS_KEY_ID=test
RW_AWS_SECRET_ACCESS_KEY=test
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
AWS_ACCESS_KEY_ID_TEST2=test2
AWS_SECRET_ACCESS_KEY_TEST2=test2
AWS_REGION=us-east-2
AWS_ENDPOINT_OVERRIDE=http://127.0.0.1:4566
```

Run the tests.

```bash
./gradlew :keystorage:test --tests '*aws*' :signing:test --tests '*aws*'
./gradlew :acceptance-tests:acceptanceTest --tests '*Aws*' --tests '*BlsSigningAcceptanceTest*' --tests '*SecpSigningAcceptanceTest*'
```

Leave `AWS_ENDPOINT_OVERRIDE` unset to run against real AWS instead, using credentials of an AWS
account: the `RW_` credentials create and delete the test secrets and KMS keys.
