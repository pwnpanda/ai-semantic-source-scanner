require "sinatra"
require "sqlite3"

# Minimal Sinatra SQL-injection target.
# Source: params[:id]. Sink: db.execute with string-interpolated SQL.
# Joern's rubysrc2cpg reports `execute` as a CWE-89 sink (see joern_queries.sc).

db = SQLite3::Database.new "users.db"

get "/user" do
  id = params[:id]
  rows = db.execute("SELECT name FROM users WHERE id = #{id}")
  rows.map { |r| r[0] }.join(", ")
end
