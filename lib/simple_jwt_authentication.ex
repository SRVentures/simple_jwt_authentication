defmodule SimpleJWTAuthentication do
  import Plug.Conn
  alias JOSE.JWT

  @moduledoc """
  A plug that checks for presence of a simple token for authentication
  """
  @behaviour Plug
  def init(opts \\ []), do: opts

  def call(conn, opts) do
    case validate_token(conn, opts) do
      {:ok, conn} -> conn
      {:error, error} -> send_error(conn, error)
    end
  end

  defp validate_token(conn, opts) do
    conn
    |> get_jwt
    |> parse_jwt
    |> case do
      {:ok, jwt} -> assign_required_fields(conn, jwt, opts)
      error -> error
    end
  end

  defp send_error(conn, error) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, ~s({ "error": #{error} }))
    |> halt
  end

  defp assign_required_fields(conn, _, []), do: {:ok, conn}
  defp assign_required_fields(conn, jwt, fields) do
    Enum.reduce(fields, {:ok, conn}, fn
      {key, path}, {:ok, conn} ->
        case get_in(jwt.fields, path) do
          nil -> {:error, "Missing field: #{inspect key}"}
          value -> {:ok, assign(conn, key, value)}
        end
      _, {:error, error} -> {:error, error}
    end)
  end

  defp parse_jwt(nil), do: {:error, "No token"}
  defp parse_jwt(jwt), do: parse_jwt(jwt, Application.get_env(:simple_jwt_authentication, :secret_key))

  defp parse_jwt(_, nil), do: {:error, "No secret key configured"}
  defp parse_jwt(jwt, secret_key) do
    jwk = %{"kty" => "oct", "k" => secret_key}

    case JWT.verify(jwk, jwt) do
      {true, jwt, _} ->
        if expired?(jwt), do: {:error, "Token has expired"}, else: {:ok, jwt}
      _ -> {:error, "Invalid token"}
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
