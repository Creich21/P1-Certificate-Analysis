import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from scipy.stats import pointbiserialr
import ast
import plotly.express as px

continuous_features = ["shannon_entropy", "token_count", "hyphen_count", "length", 
                       "unique_char_count_domain", "special_chars", "fraction_vowels", 
                       "fraction_digits", "suspicious_keywords_count"]

boolean_features=["brand_inclusion", "idn_punycode", "subdomain_only_digits", "single_char_subdomains", "idn_hymoglyph_bool"]

def load(popular_path, malicious_path, unpopular_path):
    popular_df = pd.read_csv(popular_path)
    phishing_df = pd.read_csv(malicious_path)
    unpopular_df = pd.read_csv(unpopular_path)

    
    popular_df['label'] = 0
    phishing_df['label'] = 1
    unpopular_df['label'] = 2

    df = pd.concat([popular_df, phishing_df, unpopular_df], axis=0, ignore_index=True)
    #df = pd.concat([popular_df, malicious_df,], axis=0, ignore_index=True)


    # Convert categorical columns to appropriate types
    df['idn_punycode'] = df['idn_punycode'].astype(bool)
    df['brand_inclusion'] = df['brand_inclusion'].astype(bool)
    
     # Convert string-represented lists to real lists
    df['idn_hymoglyph'] = df['idn_hymoglyph'].apply(
        lambda x: ast.literal_eval(x) if isinstance(x, str) else x
    )

    # Boolean column: empty list -> False, non-empty -> True
    df['idn_hymoglyph_bool'] = df['idn_hymoglyph'].apply(lambda x: bool(x))
    


    # Fill missing or NaN values
    # df = df.ffill()
    df['RegistrantLand'] = df['RegistrantLand'].fillna('Unknown') 
    df['hosting_asn'] = df['hosting_asn'].fillna('Unknown')


    return df

def registrant_countries(data):
    # country_counts = data['RegistrantLand'].value_counts()
    # sum= country_counts.sum()
    # print("Registrant Countries count:")
    # print(country_counts)
    # popular_country_counts = data[data['label'] == 0]['RegistrantLand'].value_counts().sum()
    # malicious_country_counts = data[data['label'] == 1]['RegistrantLand'].value_counts().sum()
    # print(f"Popular Domains: {popular_country_counts} ({(popular_country_counts/sum)*100:.2f}%)")
    # print(f"Malicious Domains: {malicious_country_counts} ({(malicious_country_counts/sum)*100:.2f}%)")

    country_count_by_label = data.groupby('label')['RegistrantLand'].apply(lambda x: x[x != 'Unknown'].count())
    print(f"Registrant Countries count by label: \n{country_count_by_label}\n")


    top_5_popular = data[data['label'] == 0]['RegistrantLand'].value_counts().head(5)
    top_5_malicious = data[data['label'] == 1]['RegistrantLand'].value_counts().head(5)
    top_5_unpopular = data[data['label'] == 2]['RegistrantLand'].value_counts().head(5)

    fig, axs = plt.subplots(1, 3, figsize=(15, 5))

    top_5_popular.plot(kind='bar', ax=axs[0], color='b')
    axs[0].set_title('Top 5 Registrant Countries - Popular')
    axs[0].set_xlabel('Country')
    axs[0].set_ylabel('Frequency')

    top_5_malicious.plot(kind='bar', ax=axs[1], color='purple')
    axs[1].set_title('Top 5 Registrant Countries - Phishing')
    axs[1].set_xlabel('Country')

    top_5_unpopular.plot(kind='bar', ax=axs[2], color='salmon')
    axs[2].set_title('Top 5 Registrant Countries - Unpopular')
    axs[2].set_xlabel('Country')

    plt.tight_layout()
    plt.show()

def hosting_providers(data):
    # provider_counts = data['hosting_asn'].value_counts()
    # sum= provider_counts.sum()
    # print("Hosting Providers counts:")
    # print(provider_counts)
    # popular_asn_counts = data[data['label'] == 0]['hosting_asn'].value_counts().sum()
    # malicious_asn_counts = data[data['label'] == 1]['hosting_asn'].value_counts().sum()
    # print(f"Popular Domains: {popular_asn_counts} ({(popular_asn_counts/sum)*100:.2f}%)")
    # print(f"Malicious Domains: {malicious_asn_counts} ({(malicious_asn_counts/sum)*100:.2f}%)")

    hosting_count_by_label = data.groupby('label')['hosting_provider'].apply(lambda x: x[x != 'Unknown'].count())
    print(f"[INFO] Count of non-null 'hosting_asn' per label:\n{hosting_count_by_label}\n")
    
    data["hosting_provider"] = data["hosting_provider"].apply(lambda x: np.nan if x == "Unknown" else x)

    top_5_popular = data[data['label'] == 0]['hosting_provider'].value_counts().dropna().head(5)
    top_5_phishing = data[data['label'] == 1]['hosting_provider'].value_counts().dropna().head(5)
    top_5_unpopular = data[data['label'] == 2]['hosting_provider'].value_counts().dropna().head(5)

    fig, axs = plt.subplots(1, 3, figsize=(15, 5))

    top_5_popular.plot(kind='bar', ax=axs[0], color='b')
    axs[0].set_title('Top 5 Hosting Providers - Popular')
    axs[0].set_xlabel('Hosting Provider')
    axs[0].set_ylabel('Frequency')

    top_5_phishing.plot(kind='bar', ax=axs[1], color='purple')
    axs[1].set_title('Top 5 Hosting Providers - Phishing')
    axs[1].set_xlabel('Hosting Provider')

    top_5_unpopular.plot(kind='bar', ax=axs[2], color='salmon')
    axs[2].set_title('Top 5 Hosting Providers - Unpopular')
    axs[2].set_xlabel('Hosting Provider')
    
    plt.tight_layout()
    plt.show()

def top_20_hosting_providers(data):
    #data["hosting_provider"] = data["hosting_provider"].apply(lambda x: np.nan if x == "Unknown" else x)

    #top_20_providers = data['hosting_provider'].value_counts().dropna().head(20)
    unique_providers = data['hosting_provider'].nunique()
    print(f"Number of unique hosting providers: {unique_providers}")
    top_providers = data[data['hosting_provider'] != "Unknown"]['hosting_provider'].value_counts()
    top_providers = top_providers.head(min(20, len(top_providers)))

    
    plt.figure(figsize=(12, 6))
    sns.barplot(y=top_providers.index, x=top_providers.values, palette='viridis')
    plt.xticks(rotation=45)
    plt.title('Top 20 Hosting Providers')
    plt.ylabel('Hosting Provider')
    plt.xlabel('Frequency')
    plt.tight_layout()
    plt.show()


def provider_country_total(data):
    country_count=data["hosting_provider_country"].value_counts()
    top_countries=country_count.head(8)
    plt.figure(figsize=(8,8))
    plt.pie(top_countries, labels=top_countries.index, autopct='%1.1f%%', startangle=140, colors=sns.color_palette('Set2', len(top_countries)))
    plt.title('Top 10 Hosting Provider Countries')
    plt.axis('equal')
    plt.show()

def provider_country_cat(data): 
    hosting_count_by_label = data.groupby('label')['hosting_provider_country'].apply(lambda x: x[x != 'Unknown'].count())
    print(f"[INFO] Count of non-null 'hosting_provider_country' per label:\n{hosting_count_by_label}\n")
    
    data["hosting_provider_country"] = data["hosting_provider_country"].apply(lambda x: np.nan if x == "Unknown" else x)

    top_5_popular = data[data['label'] == 0]['hosting_provider_country'].value_counts().dropna().head(10)
    top_5_phishing = data[data['label'] == 1]['hosting_provider_country'].value_counts().dropna().head(10)
    top_5_unpopular = data[data['label'] == 2]['hosting_provider_country'].value_counts().dropna().head(10)

    #fig, axs = plt.subplots(1, 2, figsize=(15, 5))
    fig, axs = plt.subplots(1, 3, figsize=(15, 5))

    top_5_popular.plot(kind='bar', ax=axs[0], color='b')
    axs[0].set_title('Top 5 Hosting Providers Countries - Popular')
    axs[0].set_xlabel('Country')
    axs[0].set_ylabel('Frequency')

    top_5_phishing.plot(kind='bar', ax=axs[1], color='purple')
    axs[1].set_title('Top 5 Hosting Providers Countries - Phishing')
    axs[1].set_xlabel('Country')
    #axs[1].set_ylabel('Frequency')

    top_5_unpopular.plot(kind='bar', ax=axs[2], color='salmon')
    axs[2].set_title('Top 5 Hosting Providers Countries - Unpopular')
    axs[2].set_xlabel('Country')
    #axs[2].set_ylabel('Frequency')
    
    plt.tight_layout()
    plt.show()



#def correlation(data):
#    correlations={}
#    for feature in continuous_features:
#        correlation, p_value = pointbiserialr(data[feature], data['label'] == "1")
#        correlations[feature] =(correlation, p_value)

#    for feature, (corr, p_val) in correlations.items():
#        print(f"Feature: {feature}, Point-Biserial Correlation: {corr:.4f}, P-value: {p_val:.4f}")
    
    # correlation_matrix = data[continuous_features].corr(method='spearman')
    # plt.figure(figsize=(12, 10))
    # sns.heatmap(correlation_matrix, annot=True, fmt=".2f", cmap='coolwarm', square=True)
    # plt.show()

def plot_numerical_feature_distributions(df, continuous_features):
    num_features=len(continuous_features)
    plt.figure(figsize=(15, 10))
    for i, feature in enumerate(continuous_features, 1):
        plt.subplot((num_features + 2) // 3, 3, i)
        sns.histplot(x=feature, data=df, hue="label", kde=False ,stat="probability", bins=30, common_norm=False, palette=['blue', 'purple', 'salmon'])
        plt.title(f'{feature} Distribution')
        plt.tight_layout()
    plt.show()


def kde_distirbution(df, feature):
    plt.figure(figsize=(15, 12))
    for i, feature in enumerate(continuous_features, 1):
        plt.subplot(4, 3, i)
        sns.kdeplot(
            data=df, 
            x=feature, 
            hue="label",           # Separate by class
            fill=True,             # Fill area under KDE curve
            common_norm=False,     # Normalize each class separately
            palette="Set2",        # Set color palette
            alpha=0.5             # Transparency for better overlay visibility
        )
        plt.title(f'{feature} KDE')
        plt.tight_layout()
    plt.show()


def boolean_features_distribution(df, boolean_features):
    num_features=len(boolean_features)
    plt.figure(figsize=(15, 10))
    for i,feature in enumerate(boolean_features,1):
        plt.subplot((num_features + 2) // 3, 3, i)
        sns.countplot(data=df, x=feature, hue='label', palette=['blue', 'purple', 'salmon'])
        plt.title(f'{feature} Distribution by Label')
        plt.xlabel(feature)
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
    plt.show()



def top_5_keywords(data):
    data["suspicious_keywords"] = data["suspicious_keywords"].apply(lambda x: np.nan if x == "[]" else x)
    top_5_popular = data[data['label'] == 0]['suspicious_keywords'].value_counts().dropna().head(5)
    top_5_phishing = data[data['label'] == 1]['suspicious_keywords'].value_counts().dropna().head(5)
    top_5_unpopular = data[data['label'] == 2]['suspicious_keywords'].value_counts().dropna().head(5)



    fig, axs = plt.subplots(1, 3, figsize=(15, 5))

    top_5_popular.plot(kind='bar', ax=axs[0], color='b')
    axs[0].set_title('Top 5 sus keywords - Popular')
    axs[0].set_xlabel('suspicious keywords')
    axs[0].set_ylabel('Frequency')

    top_5_phishing.plot(kind='bar', ax=axs[1], color='purple')
    axs[1].set_title('Top 5 sus keywords - Phishing')
    axs[1].set_xlabel('suspicious keywords')
    #axs[1].set_ylabel('Frequency')

    top_5_unpopular.plot(kind='bar', ax=axs[2], color='salmon')
    axs[2].set_title('Top 5 sus keywords - Unpopular')
    axs[2].set_xlabel('suspicious keywords')
    #axs[2].set_ylabel('Frequency')
    
    plt.tight_layout()
    plt.show()

def plot_dns_ttl(data):
    plt.figure(figsize=(10, 6))
    sns.histplot(data=data, x='dns_ttl', hue='label', bins=30, stat='probability', common_norm=False, palette=['blue', 'purple', 'salmon'])
    #plt.yscale('log')
    plt.title('DNS TTL Distribution')
    plt.xlabel('DNS TTL')
    plt.ylabel('probability')
    plt.show()


def main():
    # read and Load dataset
    popular_path= input("Enter path of popular dataset: ").strip()
    phishing_path= input("Enter path of phishing dataset: ").strip()
    unpopular_path= input("Enter path of unpopular dataset: ").strip()

    data = load(popular_path, phishing_path, unpopular_path)


    # display registrant countries
    #registrant_countries(data)

    # display hosting providers
    #hosting_providers(data)

    #correlation(data)

    plot_numerical_feature_distributions(data, continuous_features)

    #kde_distirbution(data, continuous_features)

    #boolean_features_distribution(data, boolean_features)

    #top_5_keywords(data)

    #plot_dns_ttl(data)

    #top_20_hosting_providers(data)

    #provider_country_total(data)

    #provider_country_cat(data)



if __name__ == "__main__":
    main()
