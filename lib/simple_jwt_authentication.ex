defmodule SimpleJWTAuthentication do
  import Plug.Conn
  alias JOSE.JWT

  @moduledoc """
  A plug that checks for presence of a simple token for authentication
  """
  @behaviour Plug
  def init(opts), do: opts

  def call(conn, _opts) do
    conn
    |> get_jwt
    |> jwt_is_valid?
    |> if do
        conn
      else
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(401, ~s({ "error": "Invalid token" }))
        |> halt
      end
  end

  defp jwt_is_valid?(nil), do: false
  defp jwt_is_valid?(jwt), do: jwt_is_valid?(jwt, Application.get_env(:simple_jwt_authentication, :secret_key))

  defp jwt_is_valid?(_, nil), do: false
  defp jwt_is_valid?(jwt, secret_key) do
    jwk = %{"kty" => "oct", "k" => secret_key}

    case JWT.verify(jwk, jwt) do
      {true, token, _} -> !expired?(token)
      _ -> false
    end
  end

  defp get_jwt(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> jwt | _] -> jwt
      _ -> nil
    end
  end

  defp expired?(%{fields: %{"exp" => exp}}) do
    DateTime.utc_now
    |> DateTime.to_unix
    |> fn now -> now > exp end.()
  end
  defp expired?(_), do: true

end
