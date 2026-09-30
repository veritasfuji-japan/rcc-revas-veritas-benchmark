from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID,TEMPERATURE,MAX_ATTEMPTS,create_completion_once
class C:
 def __init__(self): self.calls=[]
 def create(self,**kw): self.calls.append(kw); return {"ok":True}
class Client:
 def __init__(self):
  self.chat=type("Chat",(),{})(); self.chat.completions=C()
def test_exact_config_one_call():
 c=Client(); create_completion_once(client=c,messages=[],tools=[]); assert len(c.chat.completions.calls)==1; q=c.chat.completions.calls[0]; assert q["model"]==MODEL_ID=="gpt-4.1-mini-2025-04-14"; assert q["temperature"]==TEMPERATURE==0.0; assert MAX_ATTEMPTS==1
def test_error_not_retried():
 class B:
  def __init__(self): self.n=0
  def create(self,**kw): self.n+=1; raise RuntimeError("provider failure")
 c=Client(); c.chat.completions=B()
 try: create_completion_once(client=c,messages=[],tools=[])
 except RuntimeError: pass
 else: raise AssertionError("must propagate")
 assert c.chat.completions.n==1
