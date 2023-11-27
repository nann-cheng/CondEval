"""
This defines the desired circuit topology, which computes the cosine similarity between two non-normalized vectors S and V under the malicious setting, using authenticated ss and authenticated fss.   
"""
CIRCUIT_TOPOLOGY_4_NAIVE_MALICIOUS = [
    "mask_vec_s",  # masked client input data
    "mask_vec_v",  # Masked bank input data
    "alpha",
    "in_s",
    "in_v",  # Input wire random offset
    "s_v",
    "s_s",
    "v_v",  # Beaver's triples for innerproduct
    "ip_out",  # xy inner product output wire random wire, corresponding to the input wire of fss1
    "fss1",
    "ss_out",
    "vv_out",  # ss, vv inner product output wire random offset
    "ip2",  # which equals to ip_out * ip_out
    "sv_mul",  # Associated beaver's triple for previous output offsets
    "sub_Truncate",  # The random offsets associated with truncation & fss2 random offset
    "fss2",
    "beaver_a",  # authenticated beaver's triple for use in computing c1*c2
    "beaver_b",  # authenticated beaver's triple for use in computing c1*c2
    "beaver_c",  # authenticated beaver's triple for use in computing c1*c2
]


RAND_VEC_LEN = 6