defmodule Oauthex do
  defdelegate [
    token(params),
    token_secret(params),
    params_decode(response)
  ], to: :oauth

  use Behaviour
  require Lager

  defmodule Consumer do
    defstruct key: nil, secret: nil, hash: :hmac_sha1
  end

  defmodule ReqInfo do
    defstruct token: nil, secret: nil
  end

  defmodule AccInfo do
    defstruct token: nil, secret: nil
  end



  def start(_, _) do
  end

  def access_token(url, params, consumer, reqinfo) do
    result = get url, params, consumer, reqinfo
    {token, secret} = token_info result
    AccInfo.new token: token, secret: secret
  end

  def request_token(url, params, consumer) do
    result = get url, params, consumer
    {token, secret} = token_info result
    ReqInfo.new token: token, secret: secret
  end

  def token_info(result) do
    params = params_decode result
    {token(params), token_secret(params)}
  end

  def consumer_to_tuple(consumer) do
    {String.to_char_list(consumer.key), String.to_char_list(consumer.secret), consumer.hash}
  end

  def post(url, params, consumer) do
    assert_get :oauth.post url, params, consumer_to_tuple(consumer)
  end

  def post(url, params, consumer, reqinfo) do
    assert_get :oauth.post(
      url, params, consumer_to_tuple(consumer),
      reqinfo.token, reqinfo.secret, 
      [{:sync, :false}, {:stream, :self}]
    )
  end

  def get(url, consumer) do
    get(String.to_char_list(url), [], consumer)
  end

  def get(url, params, consumer) do
    assert_get :oauth.get(url, params, consumer_to_tuple (consumer))
  end

  def get(url, params, consumer, reqinfo) do
    assert_get :oauth.get(
      url, params, consumer_to_tuple(consumer), reqinfo.token, reqinfo.secret
    )
  end

  defp assert_get(result) do
    case result do
      {:ok, {{_,200,_},_,_}=data} ->
        Lager.debug 'Result: ~p', [data];
        data
      {:ok, ref} -> ref
      result ->
        Lager.error 'oauth error ~p', [result]
        raise {:oauth_error, result}
    end
  end
end
