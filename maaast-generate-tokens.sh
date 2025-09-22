mkdir -p tokens_etc

# 2) REAL OpenAI key (edit this line with your key)
printf "sk-your-openai-key-here\n" > tokens_etc/openai-token

# 3) Stub the rest so startup doesn’t fail (you can swap to real keys later)
for p in anthropic gemini azure azure-ai; do
  printf "disabled\n" > "tokens_etc/${p}-token"
done

# 4) Stub the API base files some codepaths expect 
printf "https://disabled\n" > tokens_etc/azure-api
printf "https://disabled\n" > tokens_etc/azure-ai-api

# 5) Minimal GCP ADC file (only needed if you actually use GCP/Gemini via ADC)
printf '{}\n' > tokens_etc/application_default_credentials.json
