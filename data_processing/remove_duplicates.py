import pandas

def filter_phish(data):
    filtered_data=data[data['category']=='Phishing']
    output_path=input("Enter output path for filtered data...")
    filtered_data.to_csv(output_path,index=False)




if __name__=="__main__":
    path=input("Press enter input path...(csv): ")
    data=pandas.read_csv(path)
    # data.drop_duplicates(subset=["domain_name"],keep="first", inplace=True)
    # data.to_csv(path,index=False)

    filter_phish(data)
