class TransitionBackError(Exception):
    def __init__(self, message):
        self.message = message

class Node:
    def __init__(self, node_id, is_bidirect, **kwargs):
        self.id=node_id
        self.prev=None
        self.next=None
        self.is_bidirect=is_bidirect

    def __str__(self):
        return str(self.id)    
        
    def __repr__(self):
        return "Node:{} Prev:{} Next:{}".format(self.id,self.prev,self.next)

class AsymLList:
    def __init__(self,node_id, is_bidirect=True, nodeClass=Node, **kwargs):
        self.nodeClass=nodeClass
        firstNode=self.nodeClass(node_id,is_bidirect, **kwargs)
        
        if firstNode.is_bidirect: 
            self.back=firstNode
        else:
            self.back=None           
        self.begin=firstNode
        self.last=firstNode
        self.current=None
        
    def append(self,node_id,is_bidirect=True, **kwargs):
        newNode = self.nodeClass(node_id,is_bidirect, **kwargs)
        newNode.prev = self.back 
        self.last.next = newNode  
        if newNode.is_bidirect:
            self.back = newNode
        self.last = newNode   
        return self.last
        
    def forward(self):
        result = []
        ptr = self.begin
        while ptr is not None:
            result.append(ptr)
            ptr = ptr.next
        return result    
    
    def backward(self):
        if self.back is None:
            return None
        result = []
        ptr = self.back
        while ptr is not None:
            result.append(ptr)
            ptr = ptr.prev
        return result    
            
    def fwd(self):
        if self.current is None:
            self.current=self.begin
        else: 
            self.current=self.current.next
            if self.current is None:
                self.current=self.begin
        return self.current
    
    def rwd(self):
        if self.back is None:
            raise TransitionBackError("No way back")
        if self.current is None:
            self.current = self.back
        else: 
            self.current = self.current.prev
            if self.current is None:
                self.current = self.back
        return self.current

