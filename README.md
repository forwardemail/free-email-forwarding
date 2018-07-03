# Forward Email

[![build status](https://semaphoreci.com/api/v1/niftylettuce/forward-email/branches/master/shields_badge.svg)](https://semaphoreci.com/niftylettuce/forward-email)
[![code coverage](https://img.shields.io/codecov/c/github/niftylettuce/forward-email.svg)](https://codecov.io/gh/niftylettuce/forward-email)
[![code style](https://img.shields.io/badge/code_style-XO-5ed9c7.svg)](https://github.com/sindresorhus/xo)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![made with lass](https://img.shields.io/badge/made_with-lass-95CC28.svg)](https://lass.js.org)
[![license](https://img.shields.io/github/license/niftylettuce/forward-email.svg)](<>)

> [ForwardEmail](http://forwardemail.net) is a free, encrypted, and open-source email forwarding service at <http://forwardemail.net>


## Table of Contents

* [How it works](#how-it-works)
* [Self-Hosted Requirements](#self-hosted-requirements)
* [CLI](#cli)
* [API](#api)
* [Usage](#usage)
  * [CLI](#cli-1)
  * [API](#api-1)
* [Terms of Use](#terms-of-use)
* [FAQ](#faq)
  * [Why did I create this service](#why-did-i-create-this-service)
  * [Can people unregister or register my email forwarding without my permission](#can-people-unregister-or-register-my-email-forwarding-without-my-permission)
  * [How is it free](#how-is-it-free)
  * [What is the max email size limit](#what-is-the-max-email-size-limit)
  * [Can I forward my emails from a well-known provider](#can-i-forward-my-emails-from-a-well-known-provider)
  * [Do you store emails and their contents](#do-you-store-emails-and-their-contents)
  * [Do you store logs of emails](#do-you-store-logs-of-emails)
  * [Can you read my forwarded emails](#can-you-read-my-forwarded-emails)
  * [Does it support the + symbol (e.g. for Gmail aliases)](#does-it-support-the--symbol-eg-for-gmail-aliases)
  * [Does this forward my email's headers](#does-this-forward-my-emails-headers)
  * [Is this well-tested](#is-this-well-tested)
  * [Do you pass along SMTP response messages and codes](#do-you-pass-along-smtp-response-messages-and-codes)
  * [How do you prevent spammers and ensure good email forwarding reputation](#how-do-you-prevent-spammers-and-ensure-good-email-forwarding-reputation)
  * [Can I "send mail as" with this](#can-i-send-mail-as-with-this)
  * [Can I forward unlimited emails with this](#can-i-forward-unlimited-emails-with-this)
* [Contributors](#contributors)
* [License](#license)


## How it works

> Replace `niftylettuce@gmail.com` with the email address you want to forward emails to below:

**1.** Set the following DNS MX records on your domain name:

| Name/Host/Alias    |  TTL | Record Type | Priority | Value/Answer/Destination |
| ------------------ | :--: | ----------- | -------- | ------------------------ |
| _@ or leave blank_ | 3600 | MX          | 10       | mx1.forwardemail.net     |
| _@ or leave blank_ | 3600 | MX          | 20       | mx2.forwardemail.net     |

**2.** Set (and customize) the following DNS TXT records on your domain name:

> If you are forwarding all emails from your domain to a specific address:

| Name/Host/Alias    |  TTL | Record Type | Value/Answer/Destination               |
| ------------------ | :--: | ----------- | -------------------------------------- |
| _@ or leave blank_ | 3600 | TXT         | `forward-email=niftylettuce@gmail.com` |

> If you just need to forward a single email address (e.g. `hello@niftylettuce.com` to `niftylettuce@gmail.com`; this will also forward `hello+test@niftylettuce.com` to `niftylettuce+test@gmail.com` automatically):

| Name/Host/Alias    |  TTL | Record Type | Value/Answer/Destination                     |
| ------------------ | :--: | ----------- | -------------------------------------------- |
| _@ or leave blank_ | 3600 | TXT         | `forward-email=hello:niftylettuce@gmail.com` |

> If you are forwarding multiple emails, then you'll want to separate them with a comma:

| Name/Host/Alias    |  TTL | Record Type | Value/Answer/Destination                                                    |
| ------------------ | :--: | ----------- | --------------------------------------------------------------------------- |
| _@ or leave blank_ | 3600 | TXT         | `forward-email=hello:niftylettuce@gmail.com,support:niftylettuce@gmail.com` |

> Please note that if you have multiple TXT record lines for `forward-email:` the service will only read the FIRST listed - please ensure you only have one line.

**3.** Set (and customize) the following TXT record for SPF verification for your domain name (this will allow SPF verification to pass):

> If you're using a service like AWS Route 53, then edit your existing TXT record and add the following as a new line:

| Name/Host/Alias    |  TTL | Record Type | Value/Answer/Destination                        |
| ------------------ | :--: | ----------- | ----------------------------------------------- |
| _@ or leave blank_ | 3600 | TXT         | `v=spf1 a mx include:spf.forwardemail.net ~all` |

> If you already have a similar line with `v=spf1`, then you'll need to append `include:spf.forwardemail.net` right before any existing `include:host.com` records and before the `~all` in the same line (e.g. `v=spf1 a mx include:spf.forwardemail.net include:host.com ~all`).

**4.** Send a test email to confirm it works.  Note that it might take some time for your DNS records to propagate.

---

_Optional Add-ons:_

* Add a DMARC record for your domain name by folowing the instructions at <https://dmarc.postmarkapp.com> (this will allow DMARC verification to pass).
* If the email lands in your spam folder (which it should not), you can whitelist it (e.g. here are instructions for Google <https://support.google.com/a/answer/60751?hl=en&ref_topic=1685627>)


## Self-Hosted Requirements

You'll need a server with Ubuntu, so we recommend [Digital Ocean](https://m.do.co/c/a7fe489d1b27), as it only costs $5/mo for a basic droplet.

You'll also need the following dependencies installed:

* [Node.js][node] (v8.3+) - use [nvm][] to install it on any OS (this is what runs the email forwarding service)

  * After installing `nvm` you will need to run `nvm install node`
  * We also recommend you install [yarn][], which is an alternative to [npm][]

* [Redis][] (v4.x+) - this is a fast key-value store database used for rate-limiting and preventing spammers

  * Mac (via [brew][]): `brew install redis && brew services start redis`
  * Ubuntu:

    ```sh
    sudo add-apt-repository -y ppa:chris-lea/redis-server
    sudo apt-get update
    sudo apt-get -y install redis-server
    ```

  > If you ever need to completely wipe rate-limiting records, run `redis-cli` and then type the command `FLUSHALL`

* [SpamAssassin][] - this is used to scan emails for spam (if it is not installed/detected it will not be used)

  * Ubuntu:

    ```sh
    sudo apt-get -y install spamassassin spamc python
    ```

    > If you are using a `jessie` based version of Debian (e.g. Ubuntu 16.04):

    ```sh
    systemctl enable spamassassin
    ```

    > This is due to the bug identified here: <https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=764438>
    >
    > You **must** follow the remainder of instructions here to enable it and setup automatic rule updating: <https://www.digitalocean.com/community/tutorials/how-to-install-and-setup-spamassassin-on-ubuntu-12-04>

* [ufw][] - recommended for security on Ubuntu server

  * Ubuntu:

    ```sh
    sudo apt-get -y install ufw
    ```

    ```sh
    # allow port 22
    sudo ufw allow ssh
    # allow port 25
    sudo ufw allow smtp
    # allow port 465
    sudo ufw allow smtps
    # allow port 587
    sudo ufw allow submission
    # turn on rules
    sudo ufw enable
    ```

* [authbind][] - for allowing non-root users to run on restricted ports

  * Ubuntu:

    ```sh
    sudo apt-get install authbind
    ```

    > Modify `user` with the name of your user running the email forwarding server:

    ```sh
    sudo touch /etc/authbind/byport/25
    sudo chown user:user /etc/authbind/byport/25
    sudo chmod 755 /etc/authbind/byport/25
    sudo touch /etc/authbind/byport/465
    sudo chown user:user /etc/authbind/byport/465
    sudo chmod 755 /etc/authbind/byport/465
    # note that ports in range 512-1023 need ! added
    # <http://manpages.ubuntu.com/manpages/xenial/man1/authbind.1.html>
    sudo touch /etc/authbind/byport/\!587
    sudo chown user:user /etc/authbind/byport/\!587
    sudo chmod 755 /etc/authbind/byport/\!587
    ```

* [pm2][] - for managing and running all processes

  * npm: `npm install -g pm2`
  * yarn: `yarn global add pm2`

* [openssl][] - for generating DKIM keys for your domain

  * Ubuntu: `sudo apt-get install openssl`

    > See <https://lxadm.com/Generating_DKIM_key_with_openssl> to generate a DKIM key.
    >
    > Your DNS TXT record name/host/alias should be `default._domainkey` (if you change this you'll also need to change this value via an environment flag override, see the source code for more info).
    >
    > Your DNS TXT record value should look something like this (replace the `p=` part with your actual public key generated from the above link):

    ```log
    "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCojharU7eJW+eaLulQygsc/AHx2A0gyLnSU2fPGs8mI3Fhs3EVIIRP01euHg+IljMmXz9YtU+XMfZuYdSCa9NY16XjoIgub2+lkeiHHNpURIpwQJSeHxviMOfMAZ5/xSTDDoaYY2vcKytheZeLAVK2V1SuTdTp+C6B9E6AUSu1TwIDAQAB"
    ```

* DNS records - you'll need to setup and modify your DNS records with your own self-hosted version.  See [How it works](#how-it-works) (obviously replace `forwardemail.net` with your own domain - and make sure you do DNS lookups for all related subdomains such as `mx1.forwardemail.net`, `mx2.forwardemail.net`, and `spf.forwardemail.net` – and clone them with your own).  We recommend using Amazon Route 53 for DNS hosting.


## CLI

[npm][]:

```sh
npm install -g forward-email
```

[yarn][]:

```sh
yarn global add forward-email
```


## API

[npm][]:

```sh
npm install forward-email
```

[yarn][]:

```sh
yarn add forward-email
```


## Usage

### CLI

Use PM2 in combination with an `ecosystem.json` file and `authbind` (see the example [ecosystem.json](<>) file as an example.  Basically instead of `index` in your `ecosystem.json` file, you will use the globally installed command `forward-email` instead.

### API

```js
const ForwardEmail = require('forward-email');

const forwardEmail = new ForwardEmail();

forwardEmail.listen();
```


## Terms of Use

This software and service uses the MIT License (see [LICENSE](LICENSE)).

Here's the relevant excerpt regarding its terms of use:

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


## FAQ

### Why did I create this service

I created this service after realizing that the only email forwarding services that exist now that are "free" are also closed-source and proprietary.  This means they probably read your forwarded emails.

Before creating this, of course I adhere to the "don't repeat yourself" practice - so I endlessly searched on StackOverflow, GitHub, Gists, and elsewhere for alternative solutions.

Of course there's Haraka, sendmail, postfix, and dozens of other options, but they require a lot of setup, configuration, testing, maintenance, and are not simple.  The current service offering for email forwarding is either extremely bloated, insecure, requires payment, has a convoluted setup with unsolved or undocumented bugs (that lead you down a rabbit hole of searching for hours to come up empty handed), or they're closed-source.

There's also solutions that use "serverless" technologies, such as through Amazon SES and Amazon Lambda, but again they are extremely confusing, time intensive, and no typical user I know would go to those lengths for setup (and instead would probably end up using a simpler alternative as I almost did; in exchange for lack of privacy).

Furthermore, solutions like Amazon SES do not allow you to modify the `envelope` of the SMTP request, therefore you will need to do an ugly `Reply-To` field and rewrite the `To` as well to something like `to@noreply.com` (which is really not clean).

Then there's Gmail, which costs money now for custom domains (it used to be free).  They also don't allow you to easily set up email forwarding for custom domains anymore.

There's also Zoho mail, but again that requires you signing up for an account with Zoho, and then forwarding over the emails in a configuration setting.

Put simply, there was no current email-forwarding service that was free, simple, secure, tested, and open-source.

This service solves all of these problems.

### Can people unregister or register my email forwarding without my permission

We use MX and TXT record verification, therefore if you add this service's respective MX and TXT records, then you're registered.  If you remove them, then you're unregistered.  You have ownership of your domain and DNS management, so if someone has access to that then that's a problem.

### How is it free

I built this for myself and use it regularly.  I feel bad that people are using free closed-source forwarding services and risking their privacy and security.  I also know that most of these services if not all of them don't offer all the features that come with mine.  If this thing really takes off I might ask for donations or do a pay-what-you-want model to cover server costs.

### What is the max email size limit

We default to a 25 MB size limit (the same as Gmail), which includes content, headers, and attachments.

An error with the proper response code is returned if the file size limit is exceeded.

### Can I forward my emails from a well-known provider

No, we don't support forwarding from your Gmail to another Gmail (this is just an example).

Most email service providers like Gmail, Yahoo, Hotmail, Zoho, etc. already have this feature built-in for you to use.

### Do you store emails and their contents

No, absolutely not.

### Do you store logs of emails

No, absolutely not.

### Can you read my forwarded emails

No, I cannot read your emails and I have no wish to.  Many other email forwarding providers unethically read your email.  This is not what I'm about.

The code that is deployed to the server is publicly visible on GitHub!

### Does it support the `+` symbol (e.g. for Gmail aliases)

Yes, absolutely.

### Does this forward my email's headers

Yes, absolutely.

### Is this well-tested

Yes, it has tests written with ava and also has code coverage.

### Do you pass along SMTP response messages and codes

Yes, absolutely.  For example if you're sending an email to `hello@niftylettuce.com` and it's registered to forward to `niftylettuce@gmail.com`, then the SMTP response message and code from the `gmail.com` SMTP server will be returned instead of the proxy server at `mx1.forwardemail.net` or `mx2.forwardemail.net`.

### How do you prevent spammers and ensure good email forwarding reputation

Per documentation and suggestions from Google at <https://support.google.com/a/answer/175365?hl=en>, along with best practice, including:

1. SpamAssassin - using `spamc` client to check emails and automatically reject them if they're marked as spam

   * Checks daily for updated rules
   * Spam score threshold of `5.0`
   * Uses bayes theorem and auto learning
   * Uses [other improvements](https://wiki.apache.org/spamassassin/ImproveAccuracy)

2. SPF/DKIM - through checking if an SPF record exists for a sender, and if so, we reverse-lookup the SMTP connection's remote address to validate it matches the SPF record, otherwise it's rejected.  If an SPF record does not exist, then we require DKIM verification.  If DKIM headers are passed and fail, then it is rejected as well.

3. MX - through checking if the sender's from address domain has MX records (so it's actually coming from a mail exchange/SMTP server), otherwise it's rejected

4. Disposable Email Addresses - we automatically block senders that are from the [disposable-email-domains][] list

5. FQDN - validates that senders SMTP connections are from FQDN (meaning no IP addresses, they must have a valid domain name resolved)

6. TXT - through checking if the email address the sender is trying to send to has a TXT DNS record with a valid email forwarding setup

### Can I "send mail as" with this

Not yet, though that feature is almost done being added and should be available soon.

### Can I forward unlimited emails with this

Practically yes - the only current restriction is that senders are limited to sending you `200` emails per hour.

If this limit is exceeded we send a `451` response code which tells the senders mail server to retry later.


## Contributors

| Name           | Website                    |
| -------------- | -------------------------- |
| **Nick Baugh** | <http://niftylettuce.com/> |


## License

[MIT](LICENSE) © [Nick Baugh](http://niftylettuce.com/)


##

[npm]: https://www.npmjs.com/

[yarn]: https://yarnpkg.com/

[node]: https://nodejs.org

[nvm]: https://github.com/creationix/nvm

[redis]: https://redis.io/

[brew]: https://brew.sh/

[disposable-email-domains]: https://github.com/ivolo/disposable-email-domains

[ufw]: https://help.ubuntu.com/community/UFW

[pm2]: https://github.com/Unitech/pm2

[spamassassin]: https://spamassassin.apache.org/

[authbind]: https://en.wikipedia.org/wiki/Authbind

[openssl]: https://www.openssl.org/
