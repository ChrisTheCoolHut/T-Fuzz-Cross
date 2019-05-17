import networkx as nx
 
def n_successors(node):
    successors = set()
    def __successors(n, s):
        s.add(n)
        if n != None:
            for ss in n.successors:
                if ss not in s:
                    __successors(ss, s)
        return s

    return __successors(node, successors)

def is_predecessor(cfg, n1, n2):
    '''
    Decide whether n1 is a predecessor of n2
    '''
    return nx.algorithms.edge_connectivity(cfg, n1, n2) > 0

def is_successor(cfg, n1, n2):
    '''
    Decide whether n1 is a successor of n2
    '''
    return nx.algorithms.edge_connectivity(cfg, n2, n1) > 0
