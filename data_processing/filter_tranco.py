import pandas as pd

def filter_tranco():
    domain_list = input("Insert the path of the domain dataset .dk domains): ").strip()
    tranco_list = input("Insert the path of the tranco dataset: ").strip()
    output = input("Insert the path of the output: ").strip()

    dk_domain_list = pd.read_csv(domain_list)
    tranco_list= pd.read_csv(tranco_list, header=None)

    dk_domain_list["Domæne"] = dk_domain_list["Domæne"].str.lower()
    tranco_list[1] = tranco_list[1].str.lower()

    filtered_dk_list = dk_domain_list[dk_domain_list["Domæne"].isin(tranco_list[1])]
    filtered_dk_list["label"]="popular"

    filtered_dk_list.to_csv(output, index=False)

    # filtered_dk_list.to_json(output, orient="records", force_ascii=False, indent=2)


if __name__=="__main__":
    filter_tranco()
