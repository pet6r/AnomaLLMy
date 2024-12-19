import pandas as pd
import ollama
from tqdm import tqdm
import os
import time
from datetime import datetime
import re
from collections import Counter

class LLaMACybersecurityAnalyzer:
    def __init__(self, model_name='llama3.2:3b', excel_path=None):
        # Get the current directory of this script
        current_dir = os.path.dirname(os.path.abspath(__file__))

        self.model_name = model_name
        self.excel_path = os.path.join(current_dir, '../../data/raw/mock_connections.xlsx') if excel_path is None else excel_path
        self.responses_folder = os.path.join(current_dir, '../../data/processed/')
        self.stop_words = set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'])

    def excel_to_csv(self):
        df = pd.read_excel(self.excel_path)
        csv_path = os.path.join(os.path.dirname(self.excel_path), 'mock_connections.csv')
        df.to_csv(csv_path, index=False)
        return csv_path

    def prepare_data(self, csv_path):
        df = pd.read_csv(csv_path)
        subset_df = df[['SRCIP', 'DSTIP', 'PROTOCOL', 'SRCPORT', 'DSTPORT', 'SRCMAC', 'DSTMAC', 'SRCMFG', 'DSTMFG', 'CNT', 'NOTES']]
        groups = []
        current_group = []
        for _, row in subset_df.iterrows():
            if row.isnull().all():
                if current_group:
                    groups.append(pd.DataFrame(current_group))
                    current_group = []
            else:
                current_group.append(row)
        if current_group:
            groups.append(pd.DataFrame(current_group))
        return groups

    def generate_prompt(self, groups):
        prompt = """
        You are a highly skilled virtual cybersecurity analyst specializing in identifying
        and reporting anomalous connections within an ICS (Industrial Control System) environment.
        Your task is to analyze the following connection data and provide detailed insights
        for inclusion in our security reports. Your analysis will be reviewed by human experts.

        Task Overview:
        Analyze the following connection data from an ICS environment. Each group of data represents
        a connection conversation. Some IP addresses may be from local private networks, while others
        may be external, potentially indicating internet-based communication.

        Port notes: EPH is an ephemeral port used by devices in an ICS environment. Pay attention to the outgoing and incoming ports. Provide
        context to port usage if possible.

        Response Requirements:
        For each connection conversation:
        1. Device Identification: Identify and describe the devices involved, including their manufacturer (MFG) names and MAC addresses.
        2. Communication Details: Specify the MFG names of the communicating devices, their IP addresses, and the ports used for outgoing and incoming traffic.
        Provide information about the ports used if possible.
        3. Traffic Volume: Calculate the total sum of (CNT) packets exchanged between the devices.
        4. Implications and Concerns: Analyze what is happening within each conversation. Explain if it needs further research. Note: If these connections are in the csv file it means that they weren't
        a part of the baseline/allowlist. They were picked up as an anomaly.
        """
        for i, group in enumerate(groups, start=1):
            prompt += f"\nConversation {i}:\n{group.to_string()}\n"
        return prompt

    def get_llama_response(self, prompt):
        start_time = time.time()
        stream = ollama.chat(
            model=self.model_name,
            messages=[{'role': 'user', 'content': prompt}],
            stream=True
        )

        progress_bar = tqdm(desc="Receiving response", unit="chunk")
        full_response = ""
        chunk_times = []
        chunk_start = time.time()

        for chunk in stream:
            content = chunk['message']['content']
            full_response += content
            progress_bar.update(len(content))
            chunk_times.append(time.time() - chunk_start)
            chunk_start = time.time()

        progress_bar.close()
        elapsed_time = time.time() - start_time
        return full_response, elapsed_time, chunk_times

    def calculate_metrics(self, response, elapsed_time, chunk_times):
        word_count = len(response.split())
        char_count = len(response)
        sentence_count = len(re.findall(r'\w+[.!?]', response))
        avg_word_length = char_count / word_count if word_count > 0 else 0
        avg_sentence_length = word_count / sentence_count if sentence_count > 0 else 0

        words = re.findall(r'\w+', response.lower())
        unique_words = len(set(words))
        vocabulary_richness = unique_words / word_count if word_count > 0 else 0

        avg_chunk_time = sum(chunk_times) / len(chunk_times) if chunk_times else 0
        response_rate = word_count / elapsed_time if elapsed_time > 0 else 0

        word_freq = Counter(word for word in words if word not in self.stop_words)
        top_words = word_freq.most_common(5)

        return {
            'elapsed_time': elapsed_time,
            'avg_chunk_time': avg_chunk_time,
            'response_rate': response_rate,
            'word_count': word_count,
            'char_count': char_count,
            'sentence_count': sentence_count,
            'avg_word_length': avg_word_length,
            'avg_sentence_length': avg_sentence_length,
            'vocabulary_richness': vocabulary_richness,
            'top_words': top_words
        }

    def format_metrics(self, metrics):
        return f"""
Efficiency and Content Metrics:
===============================
1. Performance Metrics:
   - Total Response Time: {metrics['elapsed_time']:.2f} seconds
   - Average Chunk Time: {metrics['avg_chunk_time']:.4f} seconds
   - Response Rate: {metrics['response_rate']:.2f} words/second

2. Content Metrics:
   - Word Count: {metrics['word_count']}
   - Character Count: {metrics['char_count']}
   - Sentence Count: {metrics['sentence_count']}
   - Average Word Length: {metrics['avg_word_length']:.2f} characters
   - Average Sentence Length: {metrics['avg_sentence_length']:.2f} words
   - Vocabulary Richness: {metrics['vocabulary_richness']:.4f}

3. Content Analysis:
   - Top 5 Most Common Words: {', '.join(f'{word} ({count})' for word, count in metrics['top_words'])}

4. Model Consistency:
   - Estimated Accuracy: N/A (requires human evaluation or benchmark comparison)
   - Response Coherence: N/A (requires human evaluation)

Note: These metrics can be compared over time to track changes in model performance and output characteristics.
===============================

"""

    def save_response_to_file(self, response):
        os.makedirs(self.responses_folder, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"llama3.2_3b_response_{timestamp}.txt"
        file_path = os.path.join(self.responses_folder, filename)
        with open(file_path, "w") as file:
            file.write(response)
        print(f"Response saved to: {file_path}")

    def run_analysis(self):
        csv_path = self.excel_to_csv()
        groups = self.prepare_data(csv_path)
        prompt = self.generate_prompt(groups)
        response, elapsed_time, chunk_times = self.get_llama_response(prompt)
        metrics = self.calculate_metrics(response, elapsed_time, chunk_times)
        formatted_metrics = self.format_metrics(metrics)
        full_output = formatted_metrics + response
        print(full_output)
        self.save_response_to_file(full_output)
        print("Response has been saved to a txt file in the 'processed' folder.")

if __name__ == "__main__":
    analyzer = LLaMACybersecurityAnalyzer()
    analyzer.run_analysis()
