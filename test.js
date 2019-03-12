const spfCheck2 = require('python-spfcheck2');

(async () => {
  const [result, explanation] = await spfCheck2(
    '178.128.149.101',
    'no-reply@forwardemail.net',
    // '20190224101108c7052c9bcc7f4abb90251e862cd0p0na@bounces.amazon.com',
    'mx1.forwardemail.net'
  );
  console.log('result', result);
  console.log('explanation', explanation);
})();
