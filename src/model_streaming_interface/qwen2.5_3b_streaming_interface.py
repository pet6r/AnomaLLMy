import pandas as pd
import ollama
import os
import time
from datetime import datetime
import re
from collections import Counter
from tqdm import tqdm
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class StreamingCybersecurityAnalyzer:
    def __init__(self, model_name='qwen2.5:3b', excel_path=None):
        current_dir = os.path.dirname(os.path.abspath(__file__))

        self.model_name = model_name
        self.excel_path = os.path.join(current_dir, '../../data/raw/mock_connections.xlsx') if excel_path is None else excel_path
        self.responses_folder = os.path.join(current_dir, '../../data/streamed_responses/')
        self.stop_words = set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'])

        # Pre-define static parts of the prompt to avoid recreating
        self.base_prompt = """
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

        # Lists to store responses and metrics for all conversations
        self.responses = []
        self.metrics_list = []

    def excel_to_csv(self):
        try:
            df = pd.read_excel(self.excel_path)
            csv_path = os.path.join(os.path.dirname(self.excel_path), 'mock_connections.csv')
            df.to_csv(csv_path, index=False)
            logging.info(f"Excel data converted to CSV at {csv_path}")
            return csv_path
        except Exception as e:
            logging.error(f"Error converting Excel to CSV: {e}")
            return None

    def prepare_data(self, csv_path):
        if not csv_path:
            logging.error("CSV path is None; cannot prepare data.")
            return []
    
        try:
            df = pd.read_csv(csv_path)
            logging.info(f"Loaded CSV data with shape: {df.shape}")
    
            # Define a subset of the data for grouping
            subset_df = df[['SRCIP', 'DSTIP', 'PROTOCOL', 'SRCPORT', 'DSTPORT', 'SRCMAC', 'DSTMAC', 'SRCMFG', 'DSTMFG', 'CNT', 'NOTES']]
    
            # Identify rows that act as group separators
            groups = []
            current_group = []
    
            for _, row in subset_df.iterrows():
                # Check if the row has critical columns as NaN (signifying a separator)
                if pd.isna(row['SRCIP']) and pd.isna(row['DSTIP']):
                    if current_group:  # If there is data collected, save it as a group
                        groups.append(pd.DataFrame(current_group))
                        current_group = []  # Reset for the next group
                else:
                    current_group.append(row)  # Collect data into the current group
    
            if current_group:
                groups.append(pd.DataFrame(current_group))  # Append any remaining group
    
            logging.info(f"Prepared {len(groups)} connection groups.")
            return groups
        except Exception as e:
            logging.error(f"Error preparing data: {e}")
            return []


    def generate_prompt(self, group):
        # Insert the group data into the base prompt
        return self.base_prompt + f"\nConversation:\n{group.to_string(index=False)}\n"

    def get_llama_response(self, prompt):
        try:
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
            logging.info(f"Response received in {elapsed_time:.2f} seconds.")
            return full_response, elapsed_time, chunk_times
        except Exception as e:
            logging.error(f"Error receiving LLM response: {e}")
            return "", 0, []

    def calculate_metrics(self, response, elapsed_time, chunk_times):
        words = re.findall(r'\w+', response.lower())
        word_count = len(words)
        char_count = len(response)
        sentence_count = len(re.findall(r'\w+[.!?]', response))
        unique_words = len(set(words))
        vocabulary_richness = unique_words / word_count if word_count > 0 else 0
        avg_chunk_time = sum(chunk_times) / len(chunk_times) if chunk_times else 0
        response_rate = word_count / elapsed_time if elapsed_time > 0 else 0

        # Get top words excluding stop words
        word_freq = Counter(word for word in words if word not in self.stop_words)
        top_words = word_freq.most_common(5)

        return {
            'elapsed_time': elapsed_time,
            'avg_chunk_time': avg_chunk_time,
            'response_rate': response_rate,
            'word_count': word_count,
            'char_count': char_count,
            'sentence_count': sentence_count,
            'avg_word_length': char_count / word_count if word_count else 0,
            'avg_sentence_length': word_count / sentence_count if sentence_count else 0,
            'vocabulary_richness': vocabulary_richness,
            'top_words': top_words
        }

    def run_analysis(self):
        csv_path = self.excel_to_csv()
        groups = self.prepare_data(csv_path)

        for i, group in enumerate(groups, start=1):
            prompt = self.generate_prompt(group)
            response, elapsed_time, chunk_times = self.get_llama_response(prompt)
            metrics = self.calculate_metrics(response, elapsed_time, chunk_times)

            self.responses.append(f"Conversation {i}:\n" + response)
            self.metrics_list.append(metrics)

        self.save_combined_response_and_metrics()

    def save_combined_response_and_metrics(self):
        os.makedirs(self.responses_folder, exist_ok=True)

        combined_response = "\n\n".join(self.responses)
        consolidated_metrics = self.consolidate_metrics()

        combined_filename = f"{self.model_name}_combined_output_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
        combined_path = os.path.join(self.responses_folder, combined_filename)
        try:
            with open(combined_path, "w") as combined_file:
                combined_file.write(consolidated_metrics + "\n\n" + combined_response)
            logging.info(f"Combined Response and Metrics saved to: {combined_path}")
        except Exception as e:
            logging.error(f"Error saving combined response and metrics: {e}")

    def consolidate_metrics(self):
        total_elapsed_time = sum(m['elapsed_time'] for m in self.metrics_list)
        avg_response_rate = sum(m['response_rate'] for m in self.metrics_list) / len(self.metrics_list)
        total_word_count = sum(m['word_count'] for m in self.metrics_list)
        total_char_count = sum(m['char_count'] for m in self.metrics_list)
        total_sentence_count = sum(m['sentence_count'] for m in self.metrics_list)

        avg_word_length = total_char_count / total_word_count if total_word_count > 0 else 0
        avg_sentence_length = total_word_count / total_sentence_count if total_sentence_count > 0 else 0
        avg_vocabulary_richness = sum(m['vocabulary_richness'] for m in self.metrics_list) / len(self.metrics_list)

        combined_word_freq = Counter()
        for metrics in self.metrics_list:
            combined_word_freq.update(dict(metrics['top_words']))
        top_5_words_combined = combined_word_freq.most_common(5)

        return f"""
Consolidated Metrics:
===============================
1. Performance Metrics:
   - Total Elapsed Time: {total_elapsed_time:.2f} seconds
   - Average Response Rate: {avg_response_rate:.2f} words/second

2. Content Metrics:
   - Total Word Count: {total_word_count}
   - Total Character Count: {total_char_count}
   - Total Sentence Count: {total_sentence_count}
   - Average Word Length: {avg_word_length:.2f} characters
   - Average Sentence Length: {avg_sentence_length:.2f} words
   - Average Vocabulary Richness: {avg_vocabulary_richness:.4f}

3. Content Analysis:
   - Top 5 Most Common Words: {', '.join(f'{word} ({count})' for word, count in top_5_words_combined)}
===============================
"""

if __name__ == "__main__":
    analyzer = StreamingCybersecurityAnalyzer()
    analyzer.run_analysis()
