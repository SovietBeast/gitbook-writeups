# You wouldn't steal a /Flag.txt

Website is static page without much functionality, but there is one _weird_ behaviour as it loads some `base64` encoded files names.

<figure><img src="../../../.gitbook/assets/Pasted image 20231027182823.png" alt=""><figcaption></figcaption></figure>

In the website source code there are two kinds of imports, ones that are encoded in plain english, and one that are encoded in base64.

<figure><img src="../../../.gitbook/assets/Pasted image 20231027182831.png" alt=""><figcaption></figcaption></figure>

There are also two different error messages for `404 File Not Found` if path starts with `assets` there are default `Flask` 404 page.&#x20;

<figure><img src="../../../.gitbook/assets/Pasted image 20231027183135.png" alt=""><figcaption></figcaption></figure>

But if path starts with anything different there is custom `Error: 404!` message. That indicates there are two different logics for accesing this paths.&#x20;

<figure><img src="../../../.gitbook/assets/Pasted image 20231027183214.png" alt=""><figcaption></figcaption></figure>

When sending data encoded as base64 that utylize basic `path traversal` thta isn't start with _assets_ there is custom message error.&#x20;

<figure><img src="../../../.gitbook/assets/Pasted image 20231027183316.png" alt=""><figcaption></figcaption></figure>

But when accesing it from any path that starts with _assets_ path traversal works

```bash
echo -n  'assets/vendor/purecounter/../../../../../../../../../../flag.txt' | base64 -w0
```

<figure><img src="../../../.gitbook/assets/Pasted image 20231027183352.png" alt=""><figcaption></figcaption></figure>
