defmodule HeaderTest do
  use ExUnit.Case

  test "decodes oauth session handle" do
    response = {{'HTTP/1.1', 200, 'OK'}, [{'cache-control', 'private'}, {'connection', 'close'}, 
        {'date', 'Fri, 08 Aug 2014 20:57:01 GMT'}, {'age', '0'}, {'server', 'ATS'}, {'vary', 'Accept-Encoding'}, 
        {'content-length', '1078'}, {'content-type', 'text/plain;charset=UTF-8'},
        {'p3p', 'policyref="http://info.yahoo.com/w3c/p3p.xml", CP="HEA PRE LOC GOV"'}], 
          'oauth_token=A%3DuweQixDh-&oauth_token_secret=f4395b11&oauth_expires_in=3600&oauth_session_handle=AB4U21M&oauth_authorization_expires_in=739952226&xoauth_yahoo_guid=YB7CK'}
    result = Oauthex.decode_header response

    session_handle = List.keyfind(result, "oauth_session_handle", 0)
    assert session_handle == {"oauth_session_handle", "AB4U21M"} 
  end

end
