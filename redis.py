import aioredis,asyncio
class Redis(object):
    instance=None
    lock=None
    _firstini=1
    def __new__(cls, *args, **kwargs):
        
        if not cls.instance:
            print('firt create')
            cls.lock=asyncio.Lock()
            cls.instance=super(Redis, cls).__new__(cls)
            
        return cls.instance

    async def connect(self):
        async with  self.__class__.lock:
            if self.__class__._firstini:
                self.__class__._firstini=0
                while 1:
                    try:
                        self.redis = await aioredis.create_redis_pool('redis://127.0.0.1:6379/6')
                        return self
                    except Exception as e:
                        await asyncio.sleep(3)
                        print(e)
            return self      
    def __await__(self):
        
        return self.connect().__await__()
    def __del__(self):
        self.redis.close()
        asyncio.get_event_loop().run_until_complete(self.redis.wait_closed())
    def __getattr__(self, *args, **kwargs):
        def decoratefunction(*args1):
            
            async def infunction(*args2, **kwargs2):
                while 1:
                    try:
                        return await getattr(self.redis,args1[0])(*args2,**kwargs2)
                        break
                    except Exception as e:
                        print(e)
                        await asyncio.sleep(2)                
                
            return infunction
        return decoratefunction(*args)
    def pipeline(self):
        return self.redis.pipeline()