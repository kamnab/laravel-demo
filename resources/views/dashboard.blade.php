<!-- // AuthController/Callback
$userInfo = $response->json();
return view('dashboard', ['userInfo' => $userInfo]); -->

<pre>{{ print_r($userInfo, true) }}</pre>