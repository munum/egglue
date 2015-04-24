<?php

/*
 * This is a PHP library that handles calling Egglue Semantic CAPTCHA. The
 * implementation is based on  reCAPTCHA's library.
 *
 * Egglue Semantic CAPTCHA -- http://www.egglue.com
 * Copyright (c) 2007 reCAPTCHA -- http://recaptcha.net
 * AUTHORS:
 *   Mike Crawford
 *   Ben Maurer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * The Egglue server URL's
 */
define("EGGLUE_API_SERVER", "http://api.egglue.com");
define("EGGLUE_VERIFY_SERVER", "api.egglue.com");


/**
 * Encodes the given data into a query string format
 * @param $data - array of string elements to be encoded
 * @return string - encoded request
 */
function _egglue_qsencode ($data) {
        $req = "";
        foreach ( $data as $key => $value )
                $req .= $key . '=' . urlencode( stripslashes($value) ) . '&';

        // Cut the last '&'
        $req=substr($req,0,strlen($req)-1);
        return $req;
}



/**
 * Submits an HTTP POST to a Egglue server
 * @param string $host
 * @param string $path
 * @param array $data
 * @param int port
 * @return array response
 */
function _egglue_http_post($host, $path, $data, $port = 80) {

        $req = _egglue_qsencode ($data);

        $http_request  = "POST $path HTTP/1.0\r\n";
        $http_request .= "Host: $host\r\n";
        $http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
        $http_request .= "Content-Length: " . strlen($req) . "\r\n";
        $http_request .= "User-Agent: Egglue/PHP\r\n";
        $http_request .= "\r\n";
        $http_request .= $req;

        $response = '';
        if( false == ( $fs = @fsockopen($host, $port, $errno, $errstr, 10) ) ) {
                die ('Could not open socket');
        }

        fwrite($fs, $http_request);

        while ( !feof($fs) )
                $response .= fgets($fs, 1160); // One TCP-IP packet
        fclose($fs);
        $response = explode("\r\n\r\n", $response, 2);

        return $response;
}


/**
 * Gets the challenge HTML (non-javascript version).
 * This is called from the browser, and the resulting Egglue HTML widget
 * is embedded within the HTML form it was called from.

 * @return string - The HTML to be embedded in the user's form.
 */
function egglue_get_html ($remoteip)
{
  $server = EGGLUE_API_SERVER;
  return '<style type="text/css"><!--#support {height:15px;width: 300px;font-size: 10px;font-style: normal;line-height: normal;text-transform: none;font-weight: normal;font-variant: normal;font-family:inherit;position: static;text-align: right;}--></style><script type="text/javascript" src="'.$server.'/challenge?uip='.$remoteip.'"></script><div id="support"><a href="http://www.egglue.com" title="Egglue" target="_blank">Egglue Powered</a></div>';

}


/**
 * A EgglueResponse is returned from egglue_check_answer()
 */
class EgglueResponse {
        var $is_valid;
        var $error;
}


/**
  * Calls an HTTP POST function to verify if the user's guess was correct
  * @param string $remoteip
  * @param string $challenge
  * @param string $responses
  * @param array $extra_params an array of extra variables to post to the server
  * @return EgglueResponse
  */
function egglue_check_answer ($remoteip, $challenge, $responses, $extra_params = array())
{

  if ($remoteip == null || $remoteip == '') {
    die ("For security reasons, you must pass the remote ip to Egglue");
  }
  
  $empty_responses = True;
  foreach ($responses as $k) {
    if (strlen($responses[$k]) != 0) {
      $empty_responses = False;
    }
  }

  //discard spam submissions
  if ($challenge == null || strlen($challenge) == 0 || $responses == null || !$empty_responses) {
    $egglue_response = new EgglueResponse();
    $egglue_response->is_valid = false;
    $egglue_response->error = 'empty-sol';
    return $egglue_response;
  }
  
  $response = _egglue_http_post (EGGLUE_VERIFY_SERVER, "/verify",
				    array (
					   'remoteip' => $remoteip,
					   'egglue_challenge' => $challenge,
					   ) + $responses + $extra_params
				    );
  $answers = explode ("\n", $response [1]);
  $egglue_response = new EgglueResponse();

  if (strtolower(trim ($answers [0])) == 'true') {
    $egglue_response->is_valid = true;
  }
  else {
    $egglue_response->is_valid = false;
    $egglue_response->error = $answers [1];
  }
  return $egglue_response;

}

?>
