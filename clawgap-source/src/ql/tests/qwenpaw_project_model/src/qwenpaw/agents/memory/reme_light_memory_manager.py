class ReMeLightMemoryManager:
    def list_memory_tools(self):
        return [self.memory_search]

    async def memory_search(self, query, max_results=5, min_score=0.1):
        return await self._reme.memory_search(
            query=query,
            max_results=max_results,
            min_score=min_score,
        )

    async def unrelated_memory_helper(self, query):
        return query
