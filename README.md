# SimpleJWTAuthentication

Authorizes user requests by verifying a JWT against a supplied secret key.
Currently only supports using the `Authorization` header with the value in the
format `Bearer YOUR_JWT`. Can also accept required fields as `opts`, where the
`key` is the field name (and what it will be assigned as on the connection), and
the `value` is the path (that will be passed in to `Kernel.get_in/2`) to the
field.

## Usage
### Phoenix Integration
  - Inside `web/router.ex` file, add plug to your pipeline like so:

  ```elixir
  defmodule MyApp.Router
    use Phoenix.Router

    pipeline :api do
      plug SimpleJWTAuthentication
    end

    scope "/", MyApp do
      pipe_through :api
      get "/hello", HelloController, :hello
    end
  end
  ```

  - With required fields

  ```elixir
  pipeline :api do
    plug SimpleJWTAuthentication, user_id: ["metadata", "user_id"]
  end

  ```

## Installation

  1. Add `simple_jwt_authentication` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:simple_jwt_authentication, "~> 0.1.0"}]
    end
    ```

  2. Ensure will need to supply the `:jose` package with a JSON Encoder/Decoder, which can be either [jiffy](https://github.com/davisp/jiffy), [jsone](https://github.com/sile/jsone), [jsx](https://github.com/talentdeficit/jsx), or [Poison](https://github.com/devinus/poison)

  3. Ensure `simple_jwt_authentication` is started before your application:

    ```elixir
    def application do
      [applications: [:simple_jwt_authentication]]
    end
    ```

  4. Configure your token in `config.exs`:
    ```elixir
    config :simple_jwt_authentication, secret: "your-secret-here"
    ```
