from openai import OpenAI

# This used to call gpt-4o; a comment is not a call.
client = OpenAI()
reply = client.chat.completions.create(model="gpt-6-luna", messages=[{"role": "user", "content": "hi"}])
