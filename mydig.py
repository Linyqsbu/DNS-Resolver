#@author Yuqiang Lin
#@email: yuqiang.lin@stonybrook.edu
import dns
import dns.name
import dns.query
import argparse
import datetime
import dns.resolver

rootServers= ("198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10","192.5.5.241","192.112.36.4",
                "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33")


def findIP(target):
    """
    send an initial request to a root server
    :param target:the domain whose ip address we are trying to find
    :return:a response containing the ip address or None
    """
    for r in rootServers:
        response=server(target,r)#ip address for the a root server
        if response:
            if response.answer:#if this response has an answer, then return this response
                for ans in response.answer:
                    if ans.rdtype==1:
                        return response
                    elif ans.rdtype==5:
                        for a in ans:
                            return findIP(str(a))

            elif response.additional:#otherwise, go through the additional section
                for addi in response.additional:
                    if addi.rdtype == 1:#ignore the RR that are not type A
                        for a in addi:
                            new_response = findIPRecursive(target,str(a))#send the query to a DNS server in the next level
                            if new_response:
                                return new_response

            elif response.authority:#in case there were no answer or additional section
                for autho in response.authority:
                    if autho.rdtype!=2:
                        continue
                    for au in autho:
                        new_addr=str(findIP((str(au))).answer[0][0])
                        new_response=findIPRecursive(target,new_addr)
                        if new_response:
                            return new_response
            return response
    return None

def findIPRecursive(target, addr, qtype=dns.rdatatype.A):
    """
    A recursive method that helps to find the ip address
    :param target: The domain whose ip address we are trying to find
    :param addr: The ip address of the dns server that we are going to
    :return: A response that contains the answer or a response that contains additional information about the domain
                or None
    """
    response=server(target,addr,qtype)#send the query to the DNS server with ip addr
    if response:
        if response.answer:#if there is an answer, return the response
            for ans in response.answer:
                if ans.rdtype == 1:
                    return response
                elif ans.rdtype == 5:
                    for a in ans:
                        return findIP(str(a))

        elif response.additional:#otherwise go through the additional section
            for addi in response.additional:
                if addi.rdtype==1:
                    for a in addi:
                        new_addr=str(a)
                        new_response=findIPRecursive(target,new_addr)
                        if new_response:
                            return new_response

        elif response.authority:#if the additional field is empty, we go through the authority field
            for autho in response.authority:
                if autho.rdtype!=2:
                    continue
                for au in autho:
                    new_addr=str(findIP(str(au)).answer[0][0])#resolve the current NS domain name
                    new_response=findIPRecursive(target,new_addr)#send the query to the resolved ip
                    if new_response:
                        return new_response

    return response

def server(target, addr, qtype=dns.rdatatype.A):
    """
    An intermediate server that makes the request and send it to an dns server via udp
    :param target: the domain whose ip address we want to find
    :param addr: the ip address of the dns server we are looking into
    :return: A response that contains the answer or additional information or None
    """
    request=dns.message.make_query(dns.name.from_text(target),qtype) #make a query
    response=dns.query.udp(request,addr)#send the query
    return response

def output(name,response,time,datetime):
    answer_str=""
    answer_str+='QUESTION SECTION:\n'
    answer_str+='{:<40} {:<10} {:<10}'.format(str(name),'IN','A')+"\n\n"
    answer_str+='ANSWER SECTION:\n'

    for answers in response.answer:
        ttl = answers.ttl
        for addr in answers:
            if addr.rdtype == 1:  # A record
                answer_str+='{:<30}{:<10} {:<10} {:<10}'.format(str(name),ttl,'IN','A') + str(addr) + '\n\n'

            if addr.rdtype==5: #CNAME record
                answer_str+='{:<30}{:<10} {:<10} {:<10}'.format(str(name),ttl,'IN','CNAME') + str(addr) + '\n\n'



    answer_str+='Query time: ' + str(round(time, 5)) + 's\n'
    answer_str+='WHEN: ' + datetime.strftime("%Y-%m-%d %H:%M:%S")+'\n'

    #file=open("mydig_output.txt",'r+')
    #file.truncate(0)
    #file.write(answer_str)
    #file.close()
    print(answer_str)


def main():
    """
    a method to take the input from the command line
    """
    now=datetime.datetime.now()
    arg_parser=argparse.ArgumentParser()

    arg_parser.add_argument("name", nargs="+")

    args=arg_parser.parse_args()

    for target in args.name:
        start=datetime.datetime.now()
        result=findIP(target)
        end=datetime.datetime.now()
        if(result.answer):
            output(target,result,(end-start).total_seconds(),now)

if __name__=="__main__":
    main()

