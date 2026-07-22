# Ruby caller/callee pair for the retrieval index test.
def handler(user_id)
  run_query(user_id)
end

def run_query(user_id)
  conn.execute("SELECT * FROM users WHERE id = #{user_id}")
end
