class ADBPGMemoryManager:
    def list_memory_tools(self):
        return [self.memory_search]

    async def memory_search(self, query, max_results=5, min_score=0.1):
        return self._client.search_memory(
            query=query,
            limit=max_results,
            min_score=min_score,
        )
