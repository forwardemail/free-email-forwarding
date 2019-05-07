# Forward Email

[![build status](https://img.shields.io/travis/niftylettuce/forward-email.svg)](https://travis-ci.org/niftylettuce/forward-email)
[![code coverage](https://img.shields.io/codecov/c/github/niftylettuce/forward-email.svg)](https://codecov.io/gh/niftylettuce/forward-email)
[![code style](https://img.shields.io/badge/code_style-XO-5ed9c7.svg)](https://github.com/sindresorhus/xo)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![made with lass](https://img.shields.io/badge/made_with-lass-95CC28.svg)](https://lass.js.org)
[![license](https://img.shields.io/github/license/niftylettuce/forward-email.svg)](<>)

> :heart: Love this project? Support <a href="https://github.com/niftylettuce" target="_blank">@niftylettuce's</a> [FOSS](https://en.wikipedia.org/wiki/Free_and_open-source_software) on <a href="https://patreon.com/niftylettuce" target="_blank">Patreon</a> or <a href="https://paypal.me/niftylettuce">PayPal</a> :unicorn:

[ForwardEmail](http://forwardemail.net) is a free, encrypted, and open-source email forwarding service for custom domains at <http://forwardemail.net>


## Table of Contents

* [How It Works](#how-it-works)
* [Send Mail As Using Gmail](#send-mail-as-using-gmail)
* [Timeline](#timeline)
* [Self-Hosted Requirements](#self-hosted-requirements)
* [CLI](#cli)
* [API](#api)
* [Usage](#usage)
  * [CLI](#cli-1)
  * [API](#api-1)
* [Service-Level Agreement](#service-level-agreement)
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
  * [How do you perform DNS lookups on domain names](#how-do-you-perform-dns-lookups-on-domain-names)
  * [How fast is this service](#how-fast-is-this-service)
* [Contributors](#contributors)
* [License](#license)


## How It Works

> <u>**IMPORTANT NOTE:**</u> Replace `niftylettuce@gmail.com` below with the email address you want to forward emails to:

**1.** Set the following DNS MX records on your domain name (having both is required):

| Name/Host/Alias    |  TTL | Record Type | Priority | Value/Answer/Destination |
| ------------------ | :--: | ----------- | -------- | ------------------------ |
| _@ or leave blank_ | 3600 | MX          | 10       | mx1.forwardemail.net     |
| _@ or leave blank_ | 3600 | MX          | 20       | mx2.forwardemail.net     |

> Note that there should be NO other MX records set on your domain name.  If there were already MX records that existed, please delete them completely.

**2.** Set (and customize) the following DNS TXT records on your domain name:

> If you are forwarding all emails from your domain, (`all@niftylettuce.com`, `hello@niftylettuce.com`, etc) to a specific address `niftylettuce@gmail.com`:

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

> As of November 2, 2018 we now have added support for multi-line TXT records!  You can now have an infinite amount of forwarding emails setup – just make sure to not wrap over 255 characters in a single-line and start each line with `forward-email=`.  An example is provided below:

| Name/Host/Alias    |  TTL | Record Type | Value/Answer/Destination                                                    |
| ------------------ | :--: | ----------- | --------------------------------------------------------------------------- |
| _@ or leave blank_ | 3600 | TXT         | `forward-email=hello:niftylettuce@gmail.com,support:niftylettuce@gmail.com` |
| _@ or leave blank_ | 3600 | TXT         | `forward-email=help:niftylettuce@gmail.com,foo:niftylettuce@gmail.com`      |
| _@ or leave blank_ | 3600 | TXT         | `forward-email=orders:niftylettuce@gmail.com,baz:niftylettuce@gmail.com`    |
| _@ or leave blank_ | 3600 | TXT         | `forward-email=info:niftylettuce@gmail.com,beep:niftylettuce@gmail.com`     |
| _@ or leave blank_ | 3600 | TXT         | `forward-email=errors:niftylettuce@gmail.com,boop:niftylettuce@gmail.com`   |

**3.** Set (and customize) the following SPF record for SPF verification for your domain name (this will allow SPF verification to pass, note that you may need to enclose this value in quotes if you are using Amazon Route53):

> Note that if you are using a service such as GoDaddy, you will need to use a TXT record type instead of an SPF record for this step.
>
> If you're using a service like AWS Route 53, then edit your existing TXT record and add the following as a new line:

| Name/Host/Alias    |  TTL | Record Type | Value/Answer/Destination                        |
| ------------------ | :--: | ----------- | ----------------------------------------------- |
| _@ or leave blank_ | 3600 | SPF         | `v=spf1 a mx include:spf.forwardemail.net -all` |

> :warning: If you are using Google Apps, you'll need to append `include:_spf.google.com` to the value above – e.g. `v=spf1 a mx include:spf.forwardemail.net include:_spf.google.com -all`.
>
> If you already have a similar line with `v=spf1`, then you'll need to append `include:spf.forwardemail.net` right before any existing `include:host.com` records and before the `-all` in the same line (e.g. `v=spf1 a mx include:spf.forwardemail.net include:host.com -all`).
>
> Note that there is a difference between `-all` and `~all`.  The `-` indicates that the SPF check should FAIL if it does not match, and `~` indicates that the SPF check should SOFTFAIL.  We recommend to use the `-all` approach to prevent domain forgery.

**4.** Send a test email to confirm it works.  Note that it might take some time for your DNS records to propagate.

**5.** Add `no-reply@forwardemail.net` to your contacts.  In the event that someone is attempting to send you an email that has a strict DMARC record policy of `reject` or `quarantine`, we will rewrite the email's `From` header with a "friendly-from".  This means the `From` will look like `Sender's Name <no-reply@forwardemail.net>` and a `Reply-To` will be added with the original sender's `From` address.  In the event that there is already a `Reply-To` set, we will not overwrite it.

**6.** If you wish to "Send Mail As" from Gmail, then you will need to follow the steps under [Send Mail As Using Gmail](#send-mail-as-using-gmail) below.

---

_Optional Add-ons:_

* Add a DMARC record for your domain name by following the instructions at <https://dmarc.postmarkapp.com> (this will allow DMARC verification to pass)
* If the email lands in your spam folder (which it should not), you can whitelist it (e.g. here are instructions for Google <https://support.google.com/a/answer/60751?hl=en&ref_topic=1685627>)
* Add the ability to "Send Mail As" from Gmail by following [Send Mail As Using Gmail](#send-mail-as-using-gmail) below


## Send Mail As Using Gmail

After you've followed the steps above in [How It Works](#how-it-works) you can follow these steps in Gmail in order to "Send Mail As" using your custom domain.

1. Assuming you are using [Gmail's Two-Factor Authentication][gmail-2fa] (strongly recommended for security), visit <https://myaccount.google.com/apppasswords>.
2. When prompted for `Select the app and device you want to generate the app password for`:
   * Select `Mail` under the drop-down for `Select app`
   * Select `Other` under the drop-down for `Select device`
   * When prompted for text input, enter your custom domain's email address you're forwarding from (e.g. `hello@niftylettuce.com` - this will help you keep track in case you use this service for multiple accounts)
3. Copy the password to your clipboard that is automatically generated
   > :warning: If you are using Google Apps, visit your admin panel [Apps > G Suite >Settings for Gmail > Advanced settings](https://admin.google.com//AdminHome#ServiceSettings/service=email&subtab=filters) and make sure to check "Allow users to send mail through an external SMTP server...". There will be some delay for this change to be activated, so please wait for ~5-10 minutes.
4. Go to [Gmail](https://gmail.com) and under [Settings > Accounts and Import > Send mail as](https://mail.google.com/mail/u/0/#settings/accounts), click `Add another email address`
5. When prompted for `Name`, enter the name that you want your email to be seen as "From" (e.g. `Niftylettuce`)
6. When prompted for `Email address`, enter the email address with the custom domain you used above (e.g. `hello@niftylettuce.com`)
7. Click `Next Step` to proceed
8. When prompted for `SMTP Server`, enter `smtp.gmail.com` and leave the port as `587`
9. When prompted for `Username`, enter the portion of your Gmail address without the `@gmail.com` part (e.g. `niftylettuce` if my email is `niftylettuce@gmail.com`)
10. When prompted for `Password`, paste from your clipboard the password you generated in step 2 above
11. Leave the radio button checked to `Secured connection using TLS`
12. Click `Add Account` to proceed
13. Open a new tab to [Gmail](https://gmail.com) and wait for your verification email to arrive (you will receive a verification code that confirms you are the owner of the email address you are attempting to "Send Mail As")
14. Once it arrives, copy and paste the verification code at the prompt you received in the previous step
15. Once you've done that, go back to the email and click the link to "confirm the request". You need to do this step and the previous step for the email to be correctly configured.
16. Done!


## Timeline

* May 6, 2019: [**@niftylettuce**](https://github.com/niftylettuce) refactored the project thanks to [**@andris9**](https://github.com/andris9) and released [v2 with major performance gains](#how-fast-is-this-service)
* November 5, 2017: [**@niftylettuce**](https://github.com/niftylettuce) released v1 of the project, with a focus to always be completely open source, transparent, private, secure, and free
* 2010-2017: [**@niftylettuce**](https://github.com/niftylettuce) grew weary from the headache of setting of mail servers for every domain or the hassle and costs of using services Google Business and Zoho


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

* [python-spfcheck2][] - for validation of SPF records, see [its requirements][python-spfcheck2] for more information

* [python-dkim-verify][] - for validation of DKIM signatures, see [its requirements][python-dkim-verify] for more information

* DNS records - you need to setup and modify your DNS records with your own self-hosted version.  See [How It Works](#how-it-works) (obviously replace `forwardemail.net` with your own domain - and make sure you do DNS lookups for all related subdomains such as `mx1.forwardemail.net`, `mx2.forwardemail.net`, and `spf.forwardemail.net` – and clone them with your own).  We recommend using Amazon Route 53 for DNS hosting.

* Reverse DNS ("rDNS") with PTR Record- - the PTR record for your server's IP address is controlled by your server provider, and therefore you need to contact your server provider to set the PTR record for you.  Services such as DigitalOcean will set a PTR record for you automatically as long as you use a fully-qualified domain name ("FQDN").

* FQDN - you'll need to set your server up to have a FQDN, you can do this by:

  ```sh
  sudo vim /etc/hosts
  ```

  ```diff
  -127.0.1.1 current-hostname
  +127.0.1.1 domain.com
  ```

  ```sh
  sudo vim /etc/hostname
  ```

  ```diff
  +domain.com
  ```

* Nameservers - we highly recommend you set your server's nameservers to `1.1.1.` (see ["How do you perform DNS lookups on domain names"](#how-do-you-perform-dns-lookups-on-domain-names) below and here is a [Digital Ocean guide][do-guide])


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

Use PM2 in combination with an `ecosystem.json` file and `authbind` (see the example [ecosystem.json](ecosystem.json) file as an example.  Basically instead of `index` in your `ecosystem.json` file, you will use the globally installed command `forward-email` instead.

### API

```js
const ForwardEmail = require('forward-email');
const os = require('os');

const config = {
  noReply: 'no-reply@forwardemail.net',
  exchanges: ['mx1.forwardemail.net', 'mx2.forwardemail.net'],
  ssl: {},
  dkim: {}
};

if (process.env.NODE_ENV === 'production') {
  config.ssl = {
    secure: process.env.SECURE === 'true',
    key: fs.readFileSync('/home/deploy/mx1.forwardemail.net.key', 'utf8'),
    cert: fs.readFileSync('/home/deploy/mx1.forwardemail.net.cert', 'utf8'),
    ca: fs.readFileSync('/home/deploy/mx1.forwardemail.net.ca', 'utf8')
  };
  config.dkim = {
    domainName: 'forwardemail.net',
    keySelector: 'default',
    privateKey: fs.readFileSync('/home/deploy/dkim-private.key', 'utf8'),
    cacheDir: os.tmpdir()
  };
}

const forwardEmail = new ForwardEmail(config);
forwardEmail.server.listen(process.env.PORT || 25);
```


## Service-Level Agreement

This project is currently a best-effort service, however note that the creators of this service also use it themselves – so you can expect reliability and security.  However this is not a binding nor enforceable SLA and again, this is a best-effort service.


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

Furthermore, solutions like Amazon SES do not allow you to modify the `envelope` of the SMTP request, therefore you will need to do an ugly `Reply-To` field and rewrite the `From` as well to something like `from@noreply.com` (which is really not clean).

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

1. DNSBL - we test senders IP's against the `zen.spamhaus.org` DNS blacklist

2. SpamAssassin - using `spamc` client to check emails and automatically reject them if they're marked as spam

   * Checks daily for updated rules
   * Spam score threshold of `5.0`
   * Uses bayes theorem and auto learning
   * Uses [other improvements](https://wiki.apache.org/spamassassin/ImproveAccuracy)

3. SPF/DKIM - through checking if an SPF record exists for a sender, and if so, we reverse-lookup the SMTP connection's remote address to validate it matches the SPF record, otherwise it's rejected.  If an SPF record does not exist, then we require DKIM verification.  If DKIM headers are passed and fail, then it is rejected as well.  If no DKIM headers are passed, then we assume that DKIM validation passes.

4. MX - through checking if the sender's from address domain has MX records (so it's actually coming from a mail exchange/SMTP server), otherwise it's rejected

5. Disposable Email Addresses - we automatically block senders that are from the [disposable-email-domains][] list

6. FQDN - validates that senders SMTP connections are from FQDN (meaning no IP addresses, they must have a valid domain name resolved)

7. TXT - through checking if the email address the sender is trying to send to has a TXT DNS record with a valid email forwarding setup

8. DMARC - we check if a DMARC record exists from the sender's FQDN, and if so, if it is `reject` or `quarantine` then we re-write the `From` of the email as a "friendly-from".  This means the `From` is set to `$originalName <no-reply@forwardemail.net>` (`$originalName` is the original From name, e.g. "John Doe" in "John Doe [john@domain.com](mailto:john@domain.com)").  Furthermore we set a `Reply-To` (if one is not already set) of the original sender's from address.

### Can I "send mail as" with this

Yes! As of October 2, 2018 we have added this feature.  See [Send Mail As Using Gmail](#send-mail-as-using-gmail) above!

### Can I forward unlimited emails with this

Practically yes - the only current restriction is that senders are limited to sending `200` emails per hour through the system.

If this limit is exceeded we send a `451` response code which tells the senders mail server to retry later.

### How do you perform DNS lookups on domain names

We use CloudFlare's privacy-first consumer DNS service (see [announcement here][cloudflare-dns]).  Note that the Python packages we use (`python-spfcheck2` and `python-dkim-verify`) do not have the means like Node.js does with `dns` and its method `dns.setServers` – therefore we set the server DNS to `1.1.1.1` which it will use as a fallback in this case.

### How fast is this service

The latest version, v2 (released on May 6, 2019) was a major rewrite from v1 and focuses on performance through streams.  [Nodemailer's][nodemailer] prolific author Andris Reinman ([@andris9](https://github.com/andris9)) helped us switch off using the `mailparser` library and use `mailsplit` instead with some custom transform logic to split the header and the body of the message without affecting the body.  This allows us to perform operations on headers very fast (such as security checks and for SPF/DKIM/DMARC compliance).

**In other words, the latest version of this service services uses streams purely now and is lightning fast.**  The older version v1 also had some logic not in the most optimal order of operations – but now v2 does less memory/network intense operations first (and returns early if possible to send a response as quickly as possible to the SMTP client).

At no point in time do we write to disk or store emails – everything is done in-memory thanks to Node.js's streams and transforms! :tada:


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

[gmail-2fa]: https://myaccount.google.com/signinoptions/two-step-verification

[python-spfcheck2]: https://github.com/niftylettuce/python-spfcheck2#requirements

[python-dkim-verify]: https://github.com/niftylettuce/python-dkim-verify#requirements

[cloudflare-dns]: https://blog.cloudflare.com/announcing-1111/

[do-guide]: https://www.digitalocean.com/community/questions/how-do-i-switch-my-dns-resolvers-away-from-google

[nodemailer]: https://github.com/nodemailer/nodemailer
