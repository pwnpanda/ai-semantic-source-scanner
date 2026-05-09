# Tiny Sinatra app with a deliberate CWE-89 SQL injection.
#
# Used as a fixture for ai-codescan's Ruby pipeline; the handler
# concatenates a request parameter directly into a SQL string, which
# CodeQL/Semgrep should both flag.

require 'sinatra'
require 'sqlite3'

DB = SQLite3::Database.new(':memory:')

get '/u' do
  user_id = params[:id]
  # CWE-89: user_id flows unparameterised into the SQL string.
  sql = "SELECT id, name FROM users WHERE id=" + user_id.to_s
  rows = DB.execute(sql)
  content_type :json
  rows.to_json
end
