# opaws: 1Password Credential Process for AWS

This is a utility that allows storing AWS credentials in 1Password, and easily using them with the [`credential_process` AWS configuration option](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html).

## Installation

1. Clone the repository
2. `npm install`
3. `npm run build`
4. `npm install --global .`

## Configuration

The tool itself requires no configuration. A few things to set up for it to work:

# 1Password CLI configuration

OPAWS requires the 1Password CLI. If you have not set this up, see [the documentation](https://developer.1password.com/docs/cli/get-started/).

### 1Password Item

1. Create a new "Secure Note" item in 1Password.
2. Give it an appropriate name.
3. Add a Text field named `access key id` and enter your AWS Access Key ID.
4. Add a Password field named `secret access key` and enter your AWS Secret Access Key.
5. If you are using MFA:
   1. See the [instructions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html#enable-virt-mfa-for-iam-user) for configuring a new virtual MFA device for your IAM user.
   2. Add a Text field named `mfa serial` and enter the MFA Serial.
   3. Add a One-Time Password field named `one-time password` and enter the Secret Key. You may also be able to use the QR code route by taking a screenshot.

### AWS Configuration Profiles

In your `.aws/config` file, set up your profiles like so:

```
[profile op]
region=us-east-1
credential_process=opaws --op-item "My Item Name"
```

There are several arguments you can pass to `opaws` to customize its behavior:

- `--op-item` - The name or ID of the item you created in 1Password.  
  To get the ID of a 1Password item, you can "Copy Private Link" and then paste the link into a text editor. It will have a query string parameter `i=<item id>`.
- `--op-vault`, `--op-account` - The 1Password vault and account where the item lives. If you have multiple accounts, you will probably need to specify `--op-account`. You should only need `--op-vault` if you have multiple items with the same name in different vaults.
- `--duration` - A [timestring](https://www.npmjs.com/package/timestring) describing how long the session should last before expiring. The default is normally [3600 seconds](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html#API_AssumeRole_RequestParameters).
- `--role-arn`, `--role-session-name` - Use to assume a role. If omitted, just generate temporary session credentials.
- `--no-cache` - By default, opaws will cache credentials until they expire. Use this to skip the cache. Generally only useful for troubleshooting purposes.
- `--debug` - Output any debug and detailed error information to the console. Generally only useful for troubleshooting purposes. Do not use in your aws config file as it will garble the JSON output that the AWS libraries are expecting.

## Usage

You should not need to do anything special to use this tool once configured. The AWS SDK will call out to opaws when it needs credentials.

#### Caching

Opaws will cache credentials to avoid excessive calls to AWS. These will be returned to the SDK if available and unexpired; otherwise opaws will retrieve your keys from 1Password and create new credentials. You may receive 1Password authorization prompts when this happens.

#### Locking

The tool uses [`cross-process-lock`](https://www.npmjs.com/package/cross-process-lock) to ensure that it does not concurrently try to access 1Password keys in multiple invocations. This is for two reasons:

1. If you're using MFA, the codes only cycle every 30 seconds, and concurrent requests that try to use the same code will fail.
2. Concurrent requests could generate multiple confusing 1Password authorization prompts.

#### GUI Applications

If you are using a GUI application that is going to use AWS SDKs (for example, Dynobase or Cyberduck), you will probably have issues with the PATH. GUI applications get a different PATH than the shell, and it is difficult to customize. The simplest workaround is to create a wrapper script:

`~/.aws/opaws-wrapper.sh`

```
#!/bin/sh

export PATH=$PATH:/path/to/node/binaries
opaws "$@"
```

`~/.aws/config`

```
[profile op]
region=us-east-1
credential_process=/Users/me/.aws/opaws-wrapper.sh --op-item "My Item Name"
```

#### Errors and Troubleshooting

The AWS SDK doesn't provide a way for the credential process to directly report problems. If opaws fails to generate credentials, it will show a system notification that there was an error, with a button to view a log file detailing what went wrong.

You can also run it on the command-line with the `--debug` flag to see the same log in the console output.

### Development

1.  Clone the repo and run `npm install`
2.  Run

        npm start -- <arguments>

    or

        npm start:debug -- <arguments>
