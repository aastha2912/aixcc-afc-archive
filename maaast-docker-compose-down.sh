# 1) Try to bring the compose stack down (handles most cases)
docker compose down -v --remove-orphans || true

# 2) Force-remove any containers still attached to that network
for id in $(docker ps -aq --filter "network=aixcc-afc-archive_default"); do
  docker rm -f "$id" || true
done

# 3) As a fallback, disconnect any remaining endpoints from the network
for id in $(docker ps -q --filter "network=aixcc-afc-archive_default"); do
  docker network disconnect -f aixcc-afc-archive_default "$id" || true
done

# 4) Remove the network
docker network rm aixcc-afc-archive_default || true

# 5) Clean up any unused networks
docker network prune -f
