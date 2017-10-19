__author__ = 'saisa_000'
import urllib
import numpy as np
import os

'''
Character Set definition
1 - Alphabets only
2 - Numbers only
3 - Alphanumeric
7 - Alphanumeric with special characters
'''

if __name__ == "__main__":
    param_values = {}
    param_charset = {}
    param_max_no_values = {}
    existing = []
    max_args_overall = 0

    file_content = open('mylog.txt', 'r')

    if not os.path.exists("log_learner"):
        os.makedirs("log_learner")
    data_line = file_content.readline()

    while data_line:
        # print data_line,
        split = data_line.split(', ')

        uri = split[0]
        args = split[1][5:].split('&')

        if 'null' in split[1] or '=' not in split[1]:
            if param_max_no_values.get((uri, 'all'), 0) == 0:
                param_max_no_values[(uri, 'all')] = 0
            data_line = file_content.readline()
            continue

        if param_max_no_values.get((uri, 'all'), 0) < len(args):
            param_max_no_values[(uri, 'all')] = len(args)

        if max_args_overall < len(args):
            max_args_overall = len(args)
        for arg in args:
            arg_name = arg[:arg.index('=')] 
            arg_value = urllib.unquote(arg[arg.index('=')+1:]).rstrip()

            if arg_value.isalpha():
                param_charset[(uri, arg_name)] = param_charset.get((uri, arg_name), 0) | 1
            elif arg_value.isdigit():
                param_charset[(uri, arg_name)] = param_charset.get((uri, arg_name), 0) | 2
            elif arg_value.isalnum():
                param_charset[(uri, arg_name)] = param_charset.get((uri, arg_name), 0) | 3
            else:
                param_charset[(uri, arg_name)] = param_charset.get((uri, arg_name), 0) | 7

            if (uri, arg_name) not in param_values:
                param_values[(uri, arg_name)] = [len(arg_value)]
            else:
                existing = param_values.get((uri, arg_name), [])
                existing.append(len(arg_value))
        data_line = file_content.readline()
    for key, values in param_values.iteritems():
        np_values = np.array(values).astype(dtype="float64")
        path = 'log_learner/' + key[0][key[0].index('/')+1:key[0].rfind('/')]
        # print 'Folder Path : ', path

        if not os.path.exists(path):
            os.makedirs(path)
        path = path + '/' + key[0][key[0].rfind('/')+1:] + '_DUMP'
        # print 'File Path : ', path

        low_std_dev = str(int(np.mean(np_values)-3*np.std(np_values)))
        high_std_dev = str(int(np.mean(np_values)+3*np.std(np_values)))
        result_1 = key[1] + '=avg_length:' + low_std_dev + '?' + high_std_dev + ',' + 'char_set:' + str(param_charset.get(key, 0))
        # print result_1

        file_write = open(path, 'a')
        file_write.write(result_1 + '\n')
        file_write.close()

    for key, values in param_max_no_values.iteritems():
        path = 'log_learner/' + key[0][key[0].index('/')+1:key[0].rfind('/')]
        if not os.path.exists(path):
            os.makedirs(path)
        path = path + '/' + key[0][key[0].rfind('/')+1:] + '_DUMP'

        result_2 = 'all=max_args:' + str(param_max_no_values.get(key, 0))
        # print result_2

        file_write = open(path, 'a')
        file_write.write(result_2 + '\n')
        file_write.close()

    result_3 = 'all=max_args:' + str(max_args_overall)

    file_write = open('log_learner/global.txt', 'w')
    file_write.write(result_3 + '\n')
    file_write.close()

    print 'File parsed.'
