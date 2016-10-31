defmodule SimpleJWTAuthenticationTest do
  use ExUnit.Case, async: false
  use Plug.Test
  alias JOSE.{JWT, JWS}

  @opts SimpleJWTAuthentication.init([])

  defmacro with_secret(secret, do: expression) do
		quote do
			Application.put_env(:simple_jwt_authentication, :secret_key,
        unquote(secret))
			unquote(expression)
			Application.put_env(:simple_jwt_authentication, :secret_key, nil)
		end
	end

  defp create_jwt(secret, opts \\ []) do
    exp = Keyword.get_lazy(opts, :exp, &create_exp/0)
    fields = Keyword.get(opts, :fields, %{})

    jwk = %{"kty" => "oct", "k" => secret}
    jws = %{"alg" => "HS256"}
    jwt = Map.merge(%{"test" => true, "exp" => exp}, fields)

    jwk
    |> JWT.sign(jws, jwt)
    |> JWS.compact
    |> elem(1)
  end

  defp create_exp(year_offset \\ 1) do
    DateTime.utc_now
    |> Map.update!(:year, &(&1 + year_offset))
    |> DateTime.to_unix
  end

  describe "without a secret" do
		test "returns a 401 status code" do
			with_secret(nil) do
				# Create a test connection
				conn = conn(:get, "/foo")

				# Invoke the plug
				conn = SimpleJWTAuthentication.call(conn, @opts)

				# Assert the response and status
				assert conn.status == 401
			end
		end
	end

  describe "with an invalid token" do
		test "returns a 401 status code" do
      secret = "c2VjcmV0"
      bad_secret = "c2VjcmV0IQ"
      with_secret(secret) do
        jwt = create_jwt(bad_secret)
        # Create a test connection
        conn =
          :get
          |> conn("/foo")
          |> put_req_header("authorization", "Bearer " <> jwt)

        # Invoke the plug
        conn = SimpleJWTAuthentication.call(conn, @opts)

        # Assert the response and status
        assert conn.status == 401
      end
		end
	end

  describe "with an expired token" do
		test "returns a 401 status code" do
      secret = "c2VjcmV0"
      with_secret(secret) do
        jwt = create_jwt(secret, exp: create_exp(-1))
        # Create a test connection
        conn =
          :get
          |> conn("/foo")
          |> put_req_header("authorization", "Bearer " <> jwt)

        # Invoke the plug
        conn = SimpleJWTAuthentication.call(conn, @opts)

        # Assert the response and status
        assert conn.status == 401
      end
		end
	end

  describe "with a valid token" do
		test "returns a 200 status code" do
      secret = "c2VjcmV0"
      with_secret(secret) do
        jwt = create_jwt(secret)
        # Create a test connection
        conn =
          :get
          |> conn("/foo")
          |> put_req_header("authorization", "Bearer " <> jwt)

        # Invoke the plug
        conn = SimpleJWTAuthentication.call(conn, @opts)

        # Assert the response and status
        assert conn.status != 401
      end
		end
	end

  describe "with missing required fields" do
		test "returns a 401 status code" do
      secret = "c2VjcmV0"
      with_secret(secret) do
        jwt = create_jwt(secret)
        # Create a test connection
        conn =
          :get
          |> conn("/foo")
          |> put_req_header("authorization", "Bearer " <> jwt)

        # Invoke the plug
        opts = SimpleJWTAuthentication.init(user_id: ["metadata", "user_id"])
        conn = SimpleJWTAuthentication.call(conn, opts)

        # Assert the response and status
        assert conn.status == 401
      end
		end
	end

  describe "with required fields" do
		test "returns a 200 status code" do
      secret = "c2VjcmV0"
      with_secret(secret) do
        jwt = create_jwt(secret, fields: %{"metadata" => %{"user_id" => 1}})
        # Create a test connection
        conn =
          :get
          |> conn("/foo")
          |> put_req_header("authorization", "Bearer " <> jwt)

        # Invoke the plug
        opts = SimpleJWTAuthentication.init(user_id: ["metadata", "user_id"])
        conn = SimpleJWTAuthentication.call(conn, opts)

        # Assert the response and status
        assert conn.status != 401
      end
		end

    test "assigns the fields" do
      secret = "c2VjcmV0"
      with_secret(secret) do
        jwt = create_jwt(secret, fields: %{"metadata" => %{"user_id" => 1}})
        # Create a test connection
        conn =
          :get
          |> conn("/foo")
          |> put_req_header("authorization", "Bearer " <> jwt)

        # Invoke the plug
        opts = SimpleJWTAuthentication.init(user_id: ["metadata", "user_id"])
        conn = SimpleJWTAuthentication.call(conn, opts)

        # Assert the response and status
        assert conn.status != 401
        assert conn.assigns[:user_id] == 1
      end
		end
	end
end
