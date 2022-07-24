import urllib.error
import pandas as pd
import numpy as np
import requests
from urllib3.util import parse_url
from urllib.parse import parse_qs
import dns.resolver
import tldextract
import time
import os
from multiprocessing import Pool, Value


class FeaturesCollection:
    """
        This class holds all the features that are gathered. Each feature is a list which represents a column of data in
        a Data Frame.

        This class is necessary to support multiprocessing because it allows each process to save its own separate data,
        then merge it all when they are all done.

        To add a feature, first add a list member to this class. Then append the list with some value
        in the 'append_features' functions. Then merge the feature in the 'merge_features' function. Finally, write the
        feature to the Data Frame in the 'write_features_to_df' function.

        To remove a feature, first remove the list member from this class. Then remove the list from the
        'append_features' functions. Then remove the list from the 'merge_features' function. Then remove the list from
        the 'write_features_to_df' function.
    """
    def __init__(self):
        # features
        self.url_length = []
        self.url_dot_qty = []
        self.url_hyphen_qty = []
        self.url_underline_qty = []
        self.url_slash_qty = []
        self.url_question_qty = []
        self.url_equals_qty = []
        self.url_at_qty = []
        self.url_and_qty = []
        self.url_exclamation_qty = []
        self.url_space_qty = []
        self.url_tilde_qty = []
        self.url_comma_qty = []
        self.url_plus_qty = []
        self.url_asterisk_qty = []
        self.url_hashtag_qty = []
        self.url_dollar_qty = []
        self.url_percent_qty = []

        self.domain_length = []
        self.domain_dot_qty = []
        self.domain_hyphen_qty = []
        self.domain_underline_qty = []
        self.domain_slash_qty = []
        self.domain_question_qty = []
        self.domain_equals_qty = []
        self.domain_at_qty = []
        self.domain_and_qty = []
        self.domain_exclamation_qty = []
        self.domain_space_qty = []
        self.domain_tilde_qty = []
        self.domain_comma_qty = []
        self.domain_plus_qty = []
        self.domain_asterisk_qty = []
        self.domain_hashtag_qty = []
        self.domain_dollar_qty = []
        self.domain_percent_qty = []

        self.path_length = []
        self.path_dot_qty = []
        self.path_hyphen_qty = []
        self.path_underline_qty = []
        self.path_slash_qty = []
        self.path_question_qty = []
        self.path_equals_qty = []
        self.path_at_qty = []
        self.path_and_qty = []
        self.path_exclamation_qty = []
        self.path_space_qty = []
        self.path_tilde_qty = []
        self.path_comma_qty = []
        self.path_plus_qty = []
        self.path_asterisk_qty = []
        self.path_hashtag_qty = []
        self.path_dollar_qty = []
        self.path_percent_qty = []

        self.param_length = []
        self.domain_in_ip = []
        self.domain_client_sever = []
        self.domain_vowels = []
        self.tld_length = []

        self.ttc = []
        self.ssl_cert = []
        self.redirects_qty = []
        self.nameservers_qty = []
        self.mx_servers_qty = []


class SpecialCharacterCount:
    """
        A class used to get a count of all the separate special characters in a string
    """
    def __init__(self, string: str):
        self.string = string
        self.string_length = len(string)
        self.dot_qty = self.string.count('.') if self.string_length > 0 else -1
        self.hyphen_qty = self.string.count('-') if self.string_length > 0 else -1
        self.underline_qty = self.string.count('_') if self.string_length > 0 else -1
        self.slash_qty = self.string.count('/') if self.string_length > 0 else -1
        self.question_qty = self.string.count('?') if self.string_length > 0 else -1
        self.equals_qty = self.string.count('=') if self.string_length > 0 else -1
        self.at_qty = self.string.count('@') if self.string_length > 0 else -1
        self.and_qty = self.string.count('&') if self.string_length > 0 else -1
        self.exclamation_qty = self.string.count('!') if self.string_length > 0 else -1
        self.space_qty = self.string.count(' ') if self.string_length > 0 else -1
        self.tilde_qty = self.string.count('~') if self.string_length > 0 else -1
        self.comma_qty = self.string.count(',') if self.string_length > 0 else -1
        self.plus_qty = self.string.count('+') if self.string_length > 0 else -1
        self.asterisk_qty = self.string.count('*') if self.string_length > 0 else -1
        self.hashtag_qty = self.string.count('#') if self.string_length > 0 else -1
        self.dollar_qty = self.string.count('$') if self.string_length > 0 else -1
        self.percent_qty = self.string.count('%') if self.string_length > 0 else -1


class LFeatures:
    """
    A class used to get lexical features from a URL
    """
    def __init__(self, t_url, parsed):
        self.url = t_url
        self.parameters = []
        self.parsed = parsed

        # find all the character counts for the entire URL
        self.url_c_count = SpecialCharacterCount(self.url)

        # find the params used, and safely find the character counts for the Domain and Path/Directory
        valid_domain = True
        valid_path = True
        if self.parsed is not None:
            # find the params used
            for param in parse_qs(self.parsed.query):
                if param not in self.parameters:
                    self.parameters.append(param)
            if self.parsed.netloc is not None:
                self.domain_c_count = SpecialCharacterCount(self.parsed.netloc)
            else:
                valid_domain = False
            if self.parsed.path is not None:
                self.path_c_count = SpecialCharacterCount(self.parsed.path)
            else:
                valid_path = False
        else:
            valid_domain = False
            valid_path = False
        if not valid_domain:
            self.domain_c_count = SpecialCharacterCount("")
        if not valid_path:
            self.path_c_count = SpecialCharacterCount("")

    def get_params_length(self):
        return len(self.parameters)

    def is_domain_in_ip_format(self):
        if self.parsed is not None:
            domain = self.parsed.netloc
            return 1 if self.parsed is not None and domain.replace('.', '').isnumeric() else 0
        else:
            return -1

    def domain_contains_server_or_client(self):
        if self.parsed is not None:
            domain = self.parsed.netloc.lower()
            return 1 if "server" in domain or "client" in domain else 0
        else:
            return -1

    def get_tld_suffix_length(self):
        ext = tldextract.extract(self.url)
        return len(ext.suffix)

    def get_qty_vowels_in_domain(self):
        if self.parsed is not None:
            d = self.parsed.netloc
            return d.count('a') + d.count('e') + d.count('i') + d.count('o') + d.count('u')
        else:
            return -1


class CFeatures:
    """
    A class used to get non-lexical features from a URL
    """
    def __init__(self, t_url, parsed):
        # init members
        self.valid_ssl_cert = None
        self.redirects = None
        self.time_to_connect = None
        self.url = t_url
        self.parsed = parsed

        # attempt a http.get request with SSL Verification, and it that fails, try again without SSL Verification
        # Note: there is a use of the raw Exception class because there is currently an error in the requests' module
        # that throws a weird exception when it cannot parse the URL
        # I think there's only 1 URL in the training dataset that causes this to happen but better be safe than sorry
        try:
            self.__get_response_and_set_properties(True)
            self.valid_ssl_cert = 1
        except requests.exceptions.SSLError:
            self.valid_ssl_cert = 0
            try:
                self.__get_response_and_set_properties(False)
            except Exception:
                self.__set_invalid_response()
        except Exception:
            self.__set_invalid_response()

    def __get_response_and_set_properties(self, ssl):
        response = requests.get(self.url, timeout=2.5, verify=ssl)
        self.__set_response_properties(response)

    def __set_response_properties(self, response):
        self.redirects = len(response.history)
        self.time_to_connect = response.elapsed.total_seconds()

    def __set_invalid_response(self):
        self.valid_ssl_cert = -1
        self.redirects = - 1
        self.time_to_connect = -1

    def __get_dns_server_result(self, query_type):
        if self.parsed is not None:
            try:
                return dns.resolver.resolve(self.parsed.netloc, query_type)
            except dns.exception.DNSException:
                return -1
        else:
            return -1

    def get_time_to_connect(self):
        return self.time_to_connect

    def has_valid_ssl_cert(self):
        return self.valid_ssl_cert

    def get_qty_redirects(self):
        return self.redirects

    def get_qty_nameservers(self):
        result = self.__get_dns_server_result("NS")
        return len(result) if result != -1 else -1

    def get_qty_mx_servers(self):
        result = self.__get_dns_server_result("MX")
        return len(result) if result != -1 else -1


def append_features(url):
    """
    Find all the features for a URL

        Parameters:
            url (str): A URL in str format
        Returns:
            f (FeaturesCollection): An object containing all the features for the input url
    """
    p = None
    try:
        p = parse_url(url)
    except urllib.error.URLError or urllib.error.HTTPError or urllib.error.ContentTooShortError:
        pass
    if p is None:
        print("Could not parse url: ", url)
    l_f = LFeatures(url, p)
    c_f = CFeatures(url, p)
    f = FeaturesCollection()

    f.url_length.append(l_f.url_c_count.string_length)
    f.url_dot_qty.append(l_f.url_c_count.dot_qty)
    f.url_hyphen_qty.append(l_f.url_c_count.hyphen_qty)
    f.url_underline_qty.append(l_f.url_c_count.underline_qty)
    f.url_slash_qty.append(l_f.url_c_count.slash_qty)
    f.url_question_qty.append(l_f.url_c_count.question_qty)
    f.url_equals_qty.append(l_f.url_c_count.equals_qty)
    f.url_at_qty.append(l_f.url_c_count.at_qty)
    f.url_and_qty.append(l_f.url_c_count.and_qty)
    f.url_exclamation_qty.append(l_f.url_c_count.exclamation_qty)
    f.url_space_qty.append(l_f.url_c_count.space_qty)
    f.url_tilde_qty.append(l_f.url_c_count.tilde_qty)
    f.url_comma_qty.append(l_f.url_c_count.comma_qty)
    f.url_plus_qty.append(l_f.url_c_count.plus_qty)
    f.url_asterisk_qty.append(l_f.url_c_count.asterisk_qty)
    f.url_hashtag_qty.append(l_f.url_c_count.hashtag_qty)
    f.url_dollar_qty.append(l_f.url_c_count.dollar_qty)
    f.url_percent_qty.append(l_f.url_c_count.percent_qty)

    f.domain_length.append(l_f.domain_c_count.string_length)
    f.domain_dot_qty.append(l_f.domain_c_count.dot_qty)
    f.domain_hyphen_qty.append(l_f.domain_c_count.hyphen_qty)
    f.domain_underline_qty.append(l_f.domain_c_count.underline_qty)
    f.domain_slash_qty.append(l_f.domain_c_count.slash_qty)
    f.domain_question_qty.append(l_f.domain_c_count.question_qty)
    f.domain_equals_qty.append(l_f.domain_c_count.equals_qty)
    f.domain_at_qty.append(l_f.domain_c_count.at_qty)
    f.domain_and_qty.append(l_f.domain_c_count.and_qty)
    f.domain_exclamation_qty.append(l_f.domain_c_count.exclamation_qty)
    f.domain_space_qty.append(l_f.domain_c_count.space_qty)
    f.domain_tilde_qty.append(l_f.domain_c_count.tilde_qty)
    f.domain_comma_qty.append(l_f.domain_c_count.comma_qty)
    f.domain_plus_qty.append(l_f.domain_c_count.plus_qty)
    f.domain_asterisk_qty.append(l_f.domain_c_count.asterisk_qty)
    f.domain_hashtag_qty.append(l_f.domain_c_count.hashtag_qty)
    f.domain_dollar_qty.append(l_f.domain_c_count.dollar_qty)
    f.domain_percent_qty.append(l_f.domain_c_count.percent_qty)

    f.path_length.append(l_f.path_c_count.string_length)
    f.path_dot_qty.append(l_f.path_c_count.dot_qty)
    f.path_hyphen_qty.append(l_f.path_c_count.hyphen_qty)
    f.path_underline_qty.append(l_f.path_c_count.underline_qty)
    f.path_slash_qty.append(l_f.path_c_count.slash_qty)
    f.path_question_qty.append(l_f.path_c_count.question_qty)
    f.path_equals_qty.append(l_f.path_c_count.equals_qty)
    f.path_at_qty.append(l_f.path_c_count.at_qty)
    f.path_and_qty.append(l_f.path_c_count.and_qty)
    f.path_exclamation_qty.append(l_f.path_c_count.exclamation_qty)
    f.path_space_qty.append(l_f.path_c_count.space_qty)
    f.path_tilde_qty.append(l_f.path_c_count.tilde_qty)
    f.path_comma_qty.append(l_f.path_c_count.comma_qty)
    f.path_plus_qty.append(l_f.path_c_count.plus_qty)
    f.path_asterisk_qty.append(l_f.path_c_count.asterisk_qty)
    f.path_hashtag_qty.append(l_f.path_c_count.hashtag_qty)
    f.path_dollar_qty.append(l_f.path_c_count.dollar_qty)
    f.path_percent_qty.append(l_f.path_c_count.percent_qty)

    f.param_length.append(l_f.get_params_length())
    f.domain_in_ip.append(l_f.is_domain_in_ip_format())
    f.domain_client_sever.append(l_f.domain_contains_server_or_client())
    f.domain_vowels.append(l_f.get_qty_vowels_in_domain())
    f.tld_length.append(l_f.get_tld_suffix_length())

    f.ttc.append(c_f.get_time_to_connect())
    f.ssl_cert.append(c_f.has_valid_ssl_cert())
    f.redirects_qty.append(c_f.get_qty_redirects())
    f.nameservers_qty.append(c_f.get_qty_nameservers())
    f.mx_servers_qty.append(c_f.get_qty_mx_servers())

    with counter.get_lock():
        counter.value += 1
    percent = int((counter.value / total_urls.value) * 100)
    if percent != last_percent.value:
        print(percent, "%")
        with last_percent.get_lock():
            last_percent.value = percent

    return f


def merge_features(f_pools: list):
    """
    Take all the FeatureCollection objects from each process/pool and merge them into one Feature collection that is
    used to write to the date frame.
    Note that len(f_pools) should equal urls_size.

        Parameters:
            f_pools (list(FeatureCollection)): A list of all the FeatureCollections objects from each separate process
    """
    merged = FeaturesCollection()
    for f in f_pools:
        merged.url_length.extend(f.url_length)
        merged.url_dot_qty.extend(f.url_dot_qty)
        merged.url_hyphen_qty.extend(f.url_hyphen_qty)
        merged.url_underline_qty.extend(f.url_underline_qty)
        merged.url_slash_qty.extend(f.url_slash_qty)
        merged.url_question_qty.extend(f.url_question_qty)
        merged.url_equals_qty.extend(f.url_equals_qty)
        merged.url_at_qty.extend(f.url_at_qty)
        merged.url_and_qty.extend(f.url_and_qty)
        merged.url_exclamation_qty.extend(f.url_exclamation_qty)
        merged.url_space_qty.extend(f.url_space_qty)
        merged.url_tilde_qty.extend(f.url_tilde_qty)
        merged.url_comma_qty.extend(f.url_comma_qty)
        merged.url_plus_qty.extend(f.url_plus_qty)
        merged.url_asterisk_qty.extend(f.url_asterisk_qty)
        merged.url_hashtag_qty.extend(f.url_hashtag_qty)
        merged.url_dollar_qty.extend(f.url_dollar_qty)
        merged.url_percent_qty.extend(f.url_percent_qty)

        merged.domain_length.extend(f.domain_length)
        merged.domain_dot_qty.extend(f.domain_dot_qty)
        merged.domain_hyphen_qty.extend(f.domain_hyphen_qty)
        merged.domain_underline_qty.extend(f.domain_underline_qty)
        merged.domain_slash_qty.extend(f.domain_slash_qty)
        merged.domain_question_qty.extend(f.domain_question_qty)
        merged.domain_equals_qty.extend(f.domain_equals_qty)
        merged.domain_at_qty.extend(f.domain_at_qty)
        merged.domain_and_qty.extend(f.domain_and_qty)
        merged.domain_exclamation_qty.extend(f.domain_exclamation_qty)
        merged.domain_space_qty.extend(f.domain_space_qty)
        merged.domain_tilde_qty.extend(f.domain_tilde_qty)
        merged.domain_comma_qty.extend(f.domain_comma_qty)
        merged.domain_plus_qty.extend(f.domain_plus_qty)
        merged.domain_asterisk_qty.extend(f.domain_asterisk_qty)
        merged.domain_hashtag_qty.extend(f.domain_hashtag_qty)
        merged.domain_dollar_qty.extend(f.domain_dollar_qty)
        merged.domain_percent_qty.extend(f.domain_percent_qty)

        merged.path_length.extend(f.path_length)
        merged.path_dot_qty.extend(f.path_dot_qty)
        merged.path_hyphen_qty.extend(f.path_hyphen_qty)
        merged.path_underline_qty.extend(f.path_underline_qty)
        merged.path_slash_qty.extend(f.path_slash_qty)
        merged.path_question_qty.extend(f.path_question_qty)
        merged.path_equals_qty.extend(f.path_equals_qty)
        merged.path_at_qty.extend(f.path_at_qty)
        merged.path_and_qty.extend(f.path_and_qty)
        merged.path_exclamation_qty.extend(f.path_exclamation_qty)
        merged.path_space_qty.extend(f.path_space_qty)
        merged.path_tilde_qty.extend(f.path_tilde_qty)
        merged.path_comma_qty.extend(f.path_comma_qty)
        merged.path_plus_qty.extend(f.path_plus_qty)
        merged.path_asterisk_qty.extend(f.path_asterisk_qty)
        merged.path_hashtag_qty.extend(f.path_hashtag_qty)
        merged.path_dollar_qty.extend(f.path_dollar_qty)
        merged.path_percent_qty.extend(f.path_percent_qty)

        merged.param_length.extend(f.param_length)
        merged.domain_in_ip.extend(f.domain_in_ip)
        merged.domain_client_sever.extend(f.domain_client_sever)
        merged.domain_vowels.extend(f.domain_vowels)
        merged.tld_length.extend(f.tld_length)

        merged.ttc.extend(f.ttc)
        merged.ssl_cert.extend(f.ssl_cert)
        merged.redirects_qty.extend(f.redirects_qty)
        merged.nameservers_qty.extend(f.nameservers_qty)
        merged.mx_servers_qty.extend(f.mx_servers_qty)
    return merged


def write_features_to_df(f):
    """
    Create a column in the data frame for each feature

        Parameters:
            f (FeaturesCollection): An object that holds a collection of features and its data
    """
    df['url_l'] = f.url_length
    df['url_dot_qty'] = f.url_dot_qty
    df['url_hyphen_qty'] = f.url_hyphen_qty
    df['url_underline_qty'] = f.url_underline_qty
    df['url_slash_qty'] = f.url_slash_qty
    df['url_question_qty'] = f.url_question_qty
    df['url_equals_qty'] = f.url_equals_qty
    df['url_at_qty'] = f.url_at_qty
    df['url_and_qty'] = f.url_and_qty
    df['url_exclamation_qty'] = f.url_exclamation_qty
    df['url_space_qty'] = f.url_space_qty
    df['url_tilde_qty'] = f.url_tilde_qty
    df['url_comma_qty'] = f.url_comma_qty
    df['url_plus_qty'] = f.url_plus_qty
    df['url_asterisk_qty'] = f.url_asterisk_qty
    df['url_hashtag_qty'] = f.url_hashtag_qty
    df['url_dollar_qty'] = f.url_dollar_qty
    df['url_percent_qty'] = f.url_percent_qty

    df['domain_length'] = f.domain_length
    df['domain_dot_qty'] = f.domain_dot_qty
    df['domain_hyphen_qty'] = f.domain_hyphen_qty
    df['domain_underline_qty'] = f.domain_underline_qty
    df['domain_slash_qty'] = f.domain_slash_qty
    df['domain_question_qty'] = f.domain_question_qty
    df['domain_equals_qty'] = f.domain_equals_qty
    df['domain_at_qty'] = f.domain_at_qty
    df['domain_and_qty'] = f.domain_and_qty
    df['domain_exclamation_qty'] = f.domain_exclamation_qty
    df['domain_space_qty'] = f.domain_space_qty
    df['domain_tilde_qty'] = f.domain_tilde_qty
    df['domain_comma_qty'] = f.domain_comma_qty
    df['domain_plus_qty'] = f.domain_plus_qty
    df['domain_asterisk_qty'] = f.domain_asterisk_qty
    df['domain_hashtag_qty'] = f.domain_hashtag_qty
    df['domain_dollar_qty'] = f.domain_dollar_qty
    df['domain_percent_qty'] = f.domain_percent_qty

    df['path_length_qty'] = f.path_length
    df['path_dot_qty'] = f.path_dot_qty
    df['path_hyphen_qty'] = f.path_hyphen_qty
    df['path_underline_qty'] = f.path_underline_qty
    df['path_slash_qty'] = f.path_slash_qty
    df['path_question_qty'] = f.path_question_qty
    df['path_equals_qty'] = f.path_equals_qty
    df['path_at_qty'] = f.path_at_qty
    df['path_and_qty'] = f.path_and_qty
    df['path_exclamation_qty'] = f.path_exclamation_qty
    df['path_space_qty'] = f.path_space_qty
    df['path_tilde_qty'] = f.path_tilde_qty
    df['path_comma_qty'] = f.path_comma_qty
    df['path_plus_qty'] = f.path_plus_qty
    df['path_asterisk_qty'] = f.path_asterisk_qty
    df['path_hashtag_qty'] = f.path_hashtag_qty
    df['path_dollar_qty'] = f.path_dollar_qty
    df['path_percent_qty'] = f.path_percent_qty

    df['param_length'] = f.param_length
    df['domain_in_ip'] = f.domain_in_ip
    df['domain_has_client_server'] = f.domain_client_sever
    df['domain_vowel_qty'] = f.domain_vowels
    df['tld_length'] = f.tld_length

    df['ttc'] = f.ttc
    df['ssl_cert'] = f.ssl_cert
    df['redirects_qty'] = f.redirects_qty
    df['nameservers_qty'] = f.nameservers_qty
    df['mx_servers_qty'] = f.mx_servers_qty


def init(c, t, p):
    """
    Helper function that initializes process shared variables for URL feature extraction

        Parameters:
            c (multiprocessing.Value): a counter that tracks the number of urls which have had its features extracted
            t (multiprocessing.Value): the total number or urls to iterate
            p (multiprocessing.Value): the last feature extraction completion percent that was printed to the console
    """
    global counter
    counter = c
    global total_urls
    total_urls = t
    global last_percent
    last_percent = p


if __name__ == '__main__':
    # start application timer
    start_time = time.time()

    # get the number of cores in the user's cpu
    cpu_count = os.cpu_count()
    print(cpu_count, "CPU Cores detected")
    print("Starting to read csv")

    # read training dataset
    df = pd.read_csv("Phishing_Mitre_Dataset_Summer_of_AI.csv")

    # get all the links from the URL column
    link_urls = np.array(df.URL)
    urls_size = link_urls.size
    print("Finished reading csv. Starting to append features across ", cpu_count, "process pools")
    print("Total URLS: ", urls_size)

    # create variables that will be shared across all processes
    counter = Value('i', 0)
    total_urls = Value('i', urls_size)
    last_percent = Value('i', -1)

    # distribute the feature appending process for each URL across a pool of processes with size of the number
    # of core in the user's cpu
    with Pool(processes=cpu_count - 1, initializer=init, initargs=(counter, total_urls, last_percent)) as pool:
        features = pool.map(append_features, link_urls)

    # wait for all processes to finish
    pool.join()
    print("Finished appending features. Starting to merge features from pools")

    # merge the collection of features from each process into one object
    m = merge_features(features)
    print("Finished merging features. Starting to write feature to the Data Frame")

    # write the merged feature object to the data frame
    write_features_to_df(m)
    print("Finished writing to the DF. Starting to write DF to a file")

    # write the df to an output.csv file
    df.to_csv('output.csv', index=False)
    print("Finished Writing")
    print("Elapsed Time: ", time.time() - start_time, "seconds")
