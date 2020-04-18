# Self Hosting


## Table of Contents

* [Requirements](#requirements)
* [Programmatic Usage](#programmatic-usage)
* [Contributors](#contributors)
* [License](#license)


## Requirements

You'll need a server with Ubuntu, so we recommend [Digital Ocean](https://m.do.co/c/a7fe489d1b27), as it only costs $5/mo for a basic droplet.

You'll also need the following dependencies installed:

* [Node.js][node] (v8.3+) - use [nvm][] to install it on any OS (this is what runs the email forwarding service)

  * After installing `nvm` you will need to run `nvm install node`
  * We also recommend you install [yarn][], which is an alternative to [npm][]

* [Redis][] (v4.x+) - this is a fast key-value store database used for rate-limiting and preventing spammers

  > _NOTE_: You can pass `rateLimit: false` as an option to your `ForwardEmail` instance to disable the Redis requirement (e.g. `const forwardEmail = new ForwardEmail({ rateLimit: false });`

  * Mac (via [brew][]): `brew install redis && brew services start redis`
  * Ubuntu:

    ```sh
    sudo add-apt-repository -y ppa:chris-lea/redis-server
    sudo apt-get update
    sudo apt-get -y install redis-server
    ```

  > If you ever need to completely wipe rate-limiting records, run `redis-cli` and then type the command `FLUSHALL`

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

* DNS records - you need to setup and modify your DNS records with your own self-hosted version.  See our [FAQ](https://forwardemail.net/faq) for more information (be sure to replace `forwardemail.net` in the FAQ instructions with your own domain - and make sure you do DNS lookups for all related subdomains such as `mx1.forwardemail.net`, `mx2.forwardemail.net`, and `spf.forwardemail.net` – and clone them with your own).  We recommend using Cloudflare or Amazon Route 53 for DNS hosting.

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

* Nameservers - we highly recommend you set your server's nameservers to `1.1.1.1` (see our [FAQ](https://forwardemail.net/faq) and here is a [TechRepublic][tr-guide] or a [Digital Ocean guide][do-guide])


## Programmatic Usage

See the [app.js](app.js) and [ecosystem.json](ecosystem.json) files for more insight.


## Contributors

| Name           | Website                    |
| -------------- | -------------------------- |
| **Nick Baugh** | <http://niftylettuce.com/> |


## License

[Business Source License 1.1](LICENSE) © [Niftylettuce, LLC.](https://niftylettuce.com/)


## 

[npm]: https://www.npmjs.com/

[yarn]: https://yarnpkg.com/

[node]: https://nodejs.org

[nvm]: https://github.com/creationix/nvm

[redis]: https://redis.io/

[brew]: https://brew.sh/

[ufw]: https://help.ubuntu.com/community/UFW

[pm2]: https://github.com/Unitech/pm2

[authbind]: https://en.wikipedia.org/wiki/Authbind

[openssl]: https://www.openssl.org/

[python-spfcheck2]: https://github.com/niftylettuce/python-spfcheck2#requirements

[python-dkim-verify]: https://github.com/niftylettuce/python-dkim-verify#requirements

[do-guide]: https://www.digitalocean.com/community/questions/how-do-i-switch-my-dns-resolvers-away-from-google

[tr-guide]: https://www.techrepublic.com/article/how-to-set-dns-nameservers-in-ubuntu-server-18-04/
