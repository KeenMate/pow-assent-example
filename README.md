# Setting up Pow'n'Assent

## Installation of Pow

Add packages in `mix.exs`
```elixir
...
defp deps() do
	...
	{:pow, "~> 1.0.25"},
	{:pow_assent, "~> 0.4.12"}
	...
end
```

```bash
mix deps.get
mix pow.install
```

## Installation of PowAssent

Run `$ mix pow_assent.install`

## Modification of existing code
There are things to alter in existing code base

### Update `config/config.exs`
```elixir
config :my_app_web, :pow,
  user: MyApp.Users.User,
  repo: MyApp.Repo
```

### Add session plug
Add `Pow.Plug.Session` plug to `lib/my_app_web/endpoint.ex` after `plug Plug.Session`:

```elixir
defmodule MyAppWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :my_app_web

  # ...

  plug Plug.Session, @session_options
  plug Pow.Plug.Session, otp_app: :my_app_web
  plug MyAppWeb.Router
end
```

### Add new routes
Last, update `lib/my_app_web/router.ex` with the Pow routes:
```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router
  use Pow.Phoenix.Router
  use PowAssent.Phoenix.Router

  # ... pipelines

  pipeline :skip_csrf_protection do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :put_secure_browser_headers
  end

  pipeline :protected do
    plug Pow.Plug.RequireAuthenticated,
      error_handler: MyAppWeb.AuthErrorHandler
  end

  pipeline :not_authenticated do
    plug Pow.Plug.RequireNotAuthenticated,
      error_handler: MyAppWeb.AuthErrorHandler
  end

  scope "/", MyAppWeb do
    pipe_through [:browser, :not_authenticated]

    get "/signup", SignupController, :signup_page
    post "/signup", SignupController, :signup
    get "/login", LoginController, :login_page
    post "/login", LoginController, :login
  end

  scope "/", MyAppWeb do
    pipe_through [:browser, :protected]

    get "/logout", LoginController, :logout
  end

  scope "/" do
    pipe_through [:browser]

    pow_assent_routes()
  end

  scope "/" do
    pipe_through :skip_csrf_protection

    pow_assent_authorization_post_callback_routes()
  end

  # ... routes
end
```

### Provide custom session and registration controllers

#### Registration controller (`lib/my_app_web/controllers/signup_controller.ex`)
```elixir
defmodule MyAppWeb.SignupController do
  use MyAppWeb, :controller

  def signup_page(conn, _params) do
    # We'll leverage `Pow.Plug`, but you can also follow the classic Phoenix way:
    # changeset = MyApp.Users.User.changeset(%MyApp.Users.User{}, %{})

    changeset = Pow.Plug.change_user(conn)

    render(conn, "signup.html", changeset: changeset)
  end

  def signup(conn, %{"user" => user_params}) do
    # We'll leverage `Pow.Plug`, but you can also follow the classic Phoenix way:
    # user =
    #   %MyApp.Users.User{}
    #   |> MyApp.Users.User.changeset(user_params)
    #   |> MyApp.Repo.insert()

    conn
    |> Pow.Plug.create_user(user_params)
    |> case do
      {:ok, _user, conn} ->
        conn
        |> put_flash(:info, "Welcome!")
        |> redirect(to: Routes.page_path(conn, :index))

      {:error, changeset, conn} ->
        render(conn, "signup.html", changeset: changeset)
    end
  end
end
```

#### Session controller (`lib/my_app_web/controllers/login_controller.ex`)
With login/logout functionality
```elixir
defmodule MyAppWeb.LoginController do
  use MyAppWeb, :controller

  def login_page(conn, _params) do
    changeset = Pow.Plug.change_user(conn)

    render(conn, "login.html", changeset: changeset)
  end

  def login(conn, %{"user" => user_params}) do
    conn
    |> Pow.Plug.authenticate_user(user_params)
    |> case do
      {:ok, conn} ->
        conn
        |> put_flash(:info, "Welcome back!")
        |> redirect(to: Routes.page_path(conn, :index))

      {:error, conn} ->
        changeset = Pow.Plug.change_user(conn, conn.params["user"])

        conn
        |> put_flash(:info, "Invalid email or password")
        |> render("login.html", changeset: changeset)
    end
  end

  def logout(conn, _params) do
    conn
    |> Pow.Plug.delete()
    |> redirect(to: Routes.page_path(conn, :index))
  end
end
```

### Provide custom auth error handler

`lib/my_app_web/handlers/auth_error_handler.ex`
```elixir
defmodule MyAppWeb.AuthErrorHandler do
  use MyAppWeb, :controller
  alias Plug.Conn

  @spec call(Conn.t(), atom()) :: Conn.t()
  def call(conn, :not_authenticated) do
    conn
    |> put_flash(:error, "You've to be authenticated first")
    |> redirect(to: Routes.login_path(conn, :login_page))
  end

  @spec call(Conn.t(), atom()) :: Conn.t()
  def call(conn, :already_authenticated) do
    conn
    |> put_flash(:error, "You're already authenticated")
    |> redirect(to: Routes.page_path(conn, :index))
  end
end
```

### Generate phoenix templates for signup and login controllers

`$ mix pow.phoenix.gen.templates`

Append `web_module: MyAppWeb` config value to existing `pow` config.
```elixir
config :my_app_web, :pow,
  user: MyApp.Users.User,
  repo: MyApp.Repo,
  web_module: MyAppWeb
```

Because we have custom controllers, the generated files need to be moved.

#### Templates
`lib/my_app_web/templates/pow/registration` -> `lib/my_app_web/templates/signup` (rename `new.html.heex` for `signup.html.heex`) <br>
`lib/my_app_web/templates/pow/session` -> `lib/my_app_web/templates/login` (rename `new.html.heex` for `login.html.heex`)

##### Login
In `lib/my_app_web/templates/login/login.html.heex`, replace `@action` with route to login POST-back: `Routes.login_path(@conn, :login)`.
Then replace link's route to signup path with: `Routes.signup_path(@conn, :signup_page)`.

##### Signup
In `lib/my_app_web/templates/signup/signup.html.heex`, replace `@action` with route to login POST-back: `Routes.signup_path(@conn, :signup)`.
Then replace link's route to login path with: `Routes.login_path(@conn, :login_page)`.

#### Views
`lib/my_app_web/views/pow/registration_view.ex` -> `lib/my_app_web/views/signup_view.ex` <br>
`lib/my_app_web/views/pow/session_view.ex` -> `lib/my_app_web/views/login_view.ex`

In these files, you need to update the module path:
  - Remove `.Pow.` namespace segment
  - Change `Registration` for `Signup` and `Session` for `Login`


## Generating PowAssent templates

`$ mix pow_assent.phoenix.gen.templates`

## Adding template to render OpenID Connect providers

Create file `lib/my_app_web/templates/login/_provider_buttons.html.heex`
```html-eex
<%= MyAppWeb.PowAssent.ViewHelpers.provider_links @conn, fn provider, _ -> %>
  <%= MyAppWeb.PowAssent.ViewHelpers.authorization_link @conn, provider, class: "btn btn-circle btn-outline-contrast me-2" do %>
    <button>
      <%= MyAppWeb.PowAssent.ViewHelpers.provider_icon(@conn, provider) %>
    </button>
  <% end %>
<% end %>
```

The created HEEx file relies on this file at `lib/my_app_web/views/pow_assent/view_helpers.ex`:
```elixir
defmodule MyAppWeb.PowAssent.ViewHelpers do
  @moduledoc """
  View helpers to render authorization links.
  """
  alias PowAssent.Plug

  alias Phoenix.{HTML, HTML.Link, HTML.Tag}
  alias PowAssent.Phoenix.AuthorizationController

  @doc """
  Generates list of authorization links for all configured providers.

  The list of providers will be fetched from the PowAssent configuration, and
  `authorization_link/2` will be called on each.

  If a user is assigned to the conn, the authorized providers for a user will
  be looked up with `PowAssent.Plug.providers_for_current_user/1`.
  `deauthorization_link/2` will be used for any already authorized providers.

  The second argument may be link options passed on to `authorization_link/2`
  or `deauthorization_link/2` respectively. It may also be a method that
  handles render callback as seen in the example below.

  ## Example

      ViewHelpers.provider_links @conn, fn provider, providers_for_user ->
        if provider in providers_for_user do
          ViewHelpers.deauthorization_link @conn, provider do
            Tag.content_tag(:span, "Remove \#{provider}", class: provider)
          end
        else
          ViewHelpers.authorization_link @conn, provider do
            Tag.content_tag(:span, "Sign in with \#{provider}", class: provider)
          end
        end
      end
  """
  @spec provider_links(Conn.t(), keyword() | ({atom(), boolean()} -> Phoenix.HTML.unsafe())) :: [HTML.safe()]
  def provider_links(conn, link_opts_or_callback \\ []) do
    providers_for_user = Plug.providers_for_current_user(conn)
    callback           = render_callback(link_opts_or_callback, conn)

    conn
    |> Plug.available_providers()
    |> Enum.map(&callback.(&1, providers_for_user))
  end

  defp render_callback(callback, _conn) when is_function(callback), do: callback
  defp render_callback(link_opts, conn) do
    fn provider, providers_for_user ->
      case provider in providers_for_user do
        true  -> deauthorization_link(conn, provider, link_opts)
        false -> authorization_link(conn, provider, link_opts)
      end
    end
  end

  @doc """
  Generates an authorization link for a provider.

  The link is used to sign up or register a user using a provider. If
  `:invited_user` is assigned to the conn, the invitation token will be passed
  on through the URL query params.
  """
  @spec authorization_link(Conn.t(), atom(), keyword(), keyword()) :: HTML.safe()
  def authorization_link(conn, provider, opts \\ [])
  def authorization_link(conn, provider, do: contents),
    do: authorization_link(conn, provider, contents, [])
  def authorization_link(conn, provider, opts) do
    msg = AuthorizationController.extension_messages(conn).login_with_provider(%{conn | params: %{"provider" => provider}})

    authorization_link(conn, provider, msg, opts)
  end
  def authorization_link(conn, provider, opts, do: contents),
    do: authorization_link(conn, provider, contents, opts)
  def authorization_link(conn, provider, contents, opts) do
    query_params = invitation_token_query_params(conn) ++ request_path_query_params(conn)

    path = AuthorizationController.routes(conn).path_for(conn, AuthorizationController, :new, [provider], query_params)
    opts = Keyword.merge(opts, to: path)

    Link.link(contents, opts)
  end

  defp invitation_token_query_params(%{assigns: %{invited_user: %{invitation_token: token}}}), do: [invitation_token: token]
  defp invitation_token_query_params(_conn), do: []

  defp request_path_query_params(%{assigns: %{request_path: request_path}}), do: [request_path: request_path]
  defp request_path_query_params(_conn), do: []

  @doc """
  Generates a provider deauthorization link.

  The link is used to remove authorization with the provider.
  """
  @spec deauthorization_link(Conn.t(), atom(), keyword()) :: HTML.safe()
  def deauthorization_link(conn, provider, opts \\ [])
  def deauthorization_link(conn, provider, do: contents),
    do: deauthorization_link(conn, provider, contents, [])
  def deauthorization_link(conn, provider, opts) do
    msg = AuthorizationController.extension_messages(conn).remove_provider_authentication(%{conn | params: %{"provider" => provider}})

    deauthorization_link(conn, provider, msg, opts)
  end
  def deauthorization_link(conn, provider, opts, do: contents),
    do: deauthorization_link(conn, provider, contents, opts)
  def deauthorization_link(conn, provider, contents, opts) do
    path = AuthorizationController.routes(conn).path_for(conn, AuthorizationController, :delete, [provider])
    opts = Keyword.merge(opts, to: path, method: :delete)

    Link.link(contents, opts)
  end

  def provider_icon(conn, provider, additional_classes \\ "") do
    Tag.content_tag(:i, "", class: provider_icon_class(conn, provider) <> " " <> additional_classes)
  end

  defp provider_icon_class(conn, provider) do
    PowAssent.Plug.fetch_config(conn)
    |> PowAssent.Config.get_provider_config(provider)
    |> Keyword.fetch!(:icon)
  end
end
```

And use it inside `lib/my_app_web/templates/login/login.html.heex`

```html-eex
...

<%= render "_provider_buttons.html", assigns %>

...
```

## Install ecto-related stuff

Note: This seems to be executed when running `mix pow.install`

`$ mix pow.ecto.install`

Configure your database connection string in your config


### Database setup to make you going (for PostgreSQL databaze)

```sql
create database my_app_dev;

create table _template_timestamps
(
  inserted_at timestamptz default now(),
  updated_at  timestamptz default now()
);

create table user_info
(
  user_id       int primary key generated always as identity,
  email         text unique not null check (length(email) <= 255),
  password_hash text,
  display_name  text
) inherits (_template_timestamps);

create table user_identity
(
  user_identity_id int primary key generated always as identity,
  provider         text unique,
  uid              text unique,
  user_id          int references user_info (user_id)
) inherits (_template_timestamps);

```

### Customization

1. Delete out `create_users` migration (to allow yourself to create your own table)
	1.1 If you already executed some migrations you will need to clean them from build too using `mix clean`
3. `$ mix ecto.create` to create the database
4. Alter `/lib/my_app/users/user.ex` to add your custom fields

Add these:
```elixir
defmodule MyApp.Users.User do
  use Ecto.Schema
  use Pow.Ecto.Schema
  use PowAssent.Ecto.Schema

  import Ecto.Changeset

  @primary_key {:user_id, :id, autogenerate: true}
  @timestamps_opts [type: :utc_datetime]
  @derive {Jason.Encoder, only: [:user_id, :display_name, :email]}

  schema "user_info" do
    field :display_name, :string

    pow_user_fields()

    timestamps()
  end

  def changeset(user_or_changeset, attrs) do
    attrs = map_name_to_display_name(attrs)

    user_or_changeset
    |> cast(attrs, [:display_name])
    |> validate_required([:display_name])
    |> pow_changeset(attrs)
    |> unique_constraint(:email, name: "uq_user_info")
  end

  def user_identity_changeset(user_or_changeset, user_identity, attrs, user_id_attrs) do
    attrs = map_name_to_display_name(attrs)

    user_or_changeset
    |> cast(attrs, [:display_name])
    |> validate_required([:display_name])
    |> pow_assent_user_identity_changeset(user_identity, attrs, user_id_attrs)
    |> unique_constraint(:email, name: "uq_user_info")
  end

  defp map_name_to_display_name(attrs) do
    case Map.pop(attrs, "name") do
      {nil, attrs} -> attrs
      {name, attrs} -> Map.put(attrs, "display_name", name)
    end
  end
end
```

## Update UserIdentities

Update file `lib/my_app/user_identities/user_identity.ex`
with this:
```elixir
defmodule MyApp.UserIdentities.UserIdentity do
  use Ecto.Schema
  use PowAssent.Ecto.UserIdentities.Schema, user: MyApp.Users.User

  @primary_key {:user_identity_id, :id, autogenerate: true}
  @pow_assent_assocs []
  @timestamps_opts [type: :utc_datetime]

  schema "user_identities" do
    pow_assent_user_identity_fields()

    belongs_to :user, MyApp.Users.User, references: :user_id

    timestamps()
  end
end
```

Dont forget to **delete** migration created for `user_identities` table

### Overriding UserIdentity.Context module
In case your `user` table's primary key name differs from `id` (in our example it's `user_id`) we need to provide custom context module at `lib/my_app/user_identities/context.ex` as well:
```elixir
defmodule MyApp.UserIdentities.Context do
  use PowAssent.Ecto.UserIdentities.Context, repo: MyApp.Repo, user: MyApp.Users.User

  alias Pow.Ecto.Context

  def get_user_by_provider_uid(provider, uid) do
    pow_assent_get_user_by_provider_uid(provider, uid)
  end

  def upsert(user, user_identity_params) do
    params = convert_params(user_identity_params)
    {uid_provider_params, additional_params} = Map.split(params, ["uid", "provider"])

    user
    |> get_for_user(uid_provider_params)
    |> case do
      nil -> insert_identity(user, params)
      identity -> update_identity(identity, additional_params)
    end
    |> user_identity_bound_different_user_error()
  end

  defp user_identity_bound_different_user_error({:error, %{errors: errors} = changeset}) do
    case unique_constraint_error?(errors, :uid_provider) do
      true -> {:error, {:bound_to_different_user, changeset}}
      false -> {:error, changeset}
    end
  end

  defp user_identity_bound_different_user_error(any), do: any

  defp convert_params(params) when is_map(params) do
    params
    |> Enum.map(&convert_param/1)
    |> :maps.from_list()
  end

  defp convert_param({:uid, value}), do: convert_param({"uid", value})
  defp convert_param({"uid", value}) when is_integer(value), do: convert_param({"uid", Integer.to_string(value)})
  defp convert_param({key, value}) when is_atom(key), do: {Atom.to_string(key), value}
  defp convert_param({key, value}) when is_binary(key), do: {key, value}

  defp insert_identity(user, user_identity_params) do
    user_identity = Ecto.build_assoc(user, :user_identities)

    user_identity
    |> user_identity.__struct__.changeset(user_identity_params)
    |> Context.do_insert(@pow_config)
  end

  defp update_identity(user_identity, additional_params) do
    user_identity
    |> user_identity.__struct__.changeset(additional_params)
    |> Context.do_update(@pow_config)
  end

  defp get_for_user(user, %{"uid" => uid, "provider" => provider}) do
    user_identity = Ecto.build_assoc(user, :user_identities).__struct__

    MyApp.Repo.get_by(user_identity, [user_id: user.user_id, provider: provider, uid: uid])
  end

  defp unique_constraint_error?(errors, field) do
    Enum.find_value(errors, false, fn
      {^field, {_msg, [constraint: :unique, constraint_name: _name]}} -> true
      _any                                                            -> false
    end)
  end

  def create_user(user_identity_params, user_params, user_id_params) do
    pow_assent_create_user(user_identity_params, user_params, user_id_params)
  end

  def delete(user, provider) do
    pow_assent_delete(user, provider)
  end

  def all(user) do
    pow_assent_all(user)
  end
end
```

#### Updating HTML templates
Previously, we added `display_name` field. This needs to be visible in our registration form as well:

Add this to your `lib/my_app_web/templates/singup/signup.html.heex` to the form
```html-eex
<%= label f, :display_name %>
<%= text_input f, :display_name %>
<%= error_tag f, :display_name %>
```

## Configure OIDC providers

```elixir
config :my_app_web, :pow_assent,
  user_identities_context: MyApp.UserIdentities.Context,
  providers: [
    github: [
      icon: "fab fa-github",
      client_id: "CLIENT_ID",
      client_secret: "CLIENT_SECRET",
      strategy: Assent.Strategy.Github
    ],
    # azure: [
    #   icon: "fab fa-microsoft"
    # ]
  ]
```

Previous code uses FontAwesome to show the GitHub icon: Add the library if you want to see it :)

## Adding login button
To allow user to log in via UI add following code to the `lib/my_app_web/templates/layout/root.html.heex` below the 'Get started' link

```html-eex
<%= if Map.get(assigns, :current_user) do %>
  <li>
    <%= link "Sign out", to: Routes.login_path(@conn, :logout) %>
  </li>
<% else %>
  <li><a href={Routes.login_path(@conn, :login_page)}>Sign in</a></li>
<% end %>
```

# Showing signed user

You can add this to `lib/my_app_web/templates/page/index.html.heex` to test that you have user login info (below the 'Peace of mind')

```html-eex
<%= if Map.get(assigns, :current_user) do %>
  <p>
    You are: <strong><%= @current_user.display_name %></strong>
  </p>
<% else %>
  You are not known to me!
<% end %>
```
