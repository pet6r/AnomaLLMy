import pandas as pd
import ollama
import os
import time
from datetime import datetime
import re
from collections import Counter
from tqdm import tqdm
import logging
import argparse
import glob

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AnomalyOllamaAnalyzer:
    # Removed self.reports_dir initialization
    def __init__(self, model_name='dolphin-llama3:8b', anomaly_dir=None, output_dir=None, specific_file=None):
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Initialize parameters
        self.model_name = model_name
        self.anomaly_dir = os.path.join(current_dir, "../detector/anomaly_logs") if anomaly_dir is None else anomaly_dir
        self.output_dir = os.path.join(current_dir, "analysis_results") if output_dir is None else output_dir
        # self.reports_dir = os.path.join(current_dir, "reports") # Removed
        self.stop_words = set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'])
        self.specific_file = specific_file
        self.current_file = None

        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        # Removed creation of reports_dir

        # Pre-define static parts of the prompt to avoid recreating
        self.base_prompt = """
        You are a highly skilled virtual cybersecurity analyst specializing in identifying
        and reporting anomalous connections within an ICS (Industrial Control System) or
        enterprise network environment.

        Your task is to analyze the following network connection data that has been flagged
        as anomalous by our baseline detection system and provide detailed insights.
        Your analysis will be included in security reports and reviewed by human experts.

        Task Overview:
        Analyze the following connection data from our network environment. Each group of data represents
        a connection conversation that was flagged as anomalous because:
        1. It contains an unknown device (OUI not in our baseline), OR
        2. It uses a protocol not in our allowed protocol baseline, OR
        3. Both of the above reasons

        Port notes: EPH is an ephemeral port (port > 1024) used by clients. Pay special attention to the protocols,
        outgoing and incoming ports, and manufacturers (MFGs).

        Response Requirements:
        For each connection group:
        1. Device Identification: Identify and describe the devices involved based on their manufacturer (MFG) names and MAC addresses.
        2. Communication Details: Specify the protocols used, IP addresses, and ports (both source and destination).
           Provide information about the purpose of the ports if known (e.g., 443 for HTTPS).
        3. Traffic Volume: Analyze the CNT field, which represents packet counts for each connection.
        4. Risk Assessment: Evaluate the risk level (Low, Medium, High, Critical) of these anomalous connections.
           Explain your reasoning based on the protocols, devices, and communication patterns.
        5. Recommendations: Suggest specific actions for security personnel (block, monitor, investigate, or allow).

        Format your response using clear headings and bullet points for readability. Security personnel will use
        your analysis to make decisions about these anomalous connections.
        """

        # Lists to store responses and metrics for all conversations
        self.responses = []
        self.metrics_list = []
        self.analyzed_files = []

    def find_latest_anomaly_file(self):
        """Find the most recent anomaly CSV file in the anomaly directory"""
        try:
            csv_files = glob.glob(os.path.join(self.anomaly_dir, "anomalies_*.csv"))
            if not csv_files:
                logging.error(f"No anomaly CSV files found in {self.anomaly_dir}")
                return None
            latest_file = max(csv_files, key=os.path.getmtime)
            logging.info(f"Found latest anomaly file: {latest_file}")
            return latest_file
        except Exception as e:
            logging.error(f"Error finding latest anomaly file: {e}")
            return None

    def find_unanalyzed_files(self):
        """Find all anomaly CSV files that haven't been analyzed yet"""
        try:
            csv_files = glob.glob(os.path.join(self.anomaly_dir, "anomalies_*.csv"))
            if not csv_files:
                logging.error(f"No anomaly CSV files found in {self.anomaly_dir}")
                return []
            analyzed_tracker = os.path.join(self.output_dir, "analyzed_files.txt")
            analyzed_files = set()
            if os.path.exists(analyzed_tracker):
                with open(analyzed_tracker, 'r') as f:
                    analyzed_files = set(line.strip() for line in f)
            unanalyzed = [f for f in csv_files if os.path.basename(f) not in analyzed_files]
            logging.info(f"Found {len(unanalyzed)} unanalyzed anomaly files")
            return unanalyzed
        except Exception as e:
            logging.error(f"Error finding unanalyzed files: {e}")
            return []

    def prepare_data(self, csv_path):
        if not csv_path or not os.path.exists(csv_path):
            logging.error(f"CSV path {csv_path} does not exist; cannot prepare data.")
            return []
        try:
            df = pd.read_csv(csv_path)
            logging.info(f"Loaded CSV data from {csv_path} with shape: {df.shape}")
            if df.empty:
                logging.warning(f"CSV file {csv_path} is empty.")
                return []
            groups = []
            current_group = []
            for _, row in df.iterrows():
                is_separator = all(pd.isna(row[col]) for col in df.columns)
                if is_separator:
                    if current_group:
                        groups.append(pd.DataFrame(current_group))
                        current_group = []
                else:
                    current_group.append(row)
            if current_group:
                groups.append(pd.DataFrame(current_group))
            logging.info(f"Prepared {len(groups)} connection groups from {csv_path}.")
            return groups
        except Exception as e:
            logging.error(f"Error preparing data from {csv_path}: {e}")
            return []

    def generate_prompt(self, group, csv_filename):
        timestamp_match = re.search(r'anomalies_(\d{8})_(\d{6})', csv_filename)
        timestamp_str = ""
        if timestamp_match:
            date_part = timestamp_match.group(1)
            time_part = timestamp_match.group(2)
            timestamp_str = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:]} {time_part[:2]}:{time_part[2:4]}:{time_part[4:]}"
        context = f"\nThis anomalous connection data was captured at: {timestamp_str}\nSource file: {csv_filename}\n"
        group_text = group.to_string(index=False)
        return self.base_prompt + context + f"\nAnomalous Connection Group:\n{group_text}\n"

    def get_ollama_response(self, prompt):
        try:
            start_time = time.time()
            stream = ollama.chat(
                model=self.model_name,
                messages=[{'role': 'user', 'content': prompt}],
                stream=True
            )
            progress_bar = tqdm(desc="Receiving LLM response", unit="chunk")
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
            logging.error(f"Error receiving Ollama response: {e}")
            return f"Error: Failed to get LLM response: {str(e)}", 0, []

    def calculate_metrics(self, response, elapsed_time, chunk_times):
        words = re.findall(r'\w+', response.lower())
        word_count = len(words)
        char_count = len(response)
        sentence_count = len(re.findall(r'\w+[.!?]', response))
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
            'avg_word_length': char_count / word_count if word_count else 0,
            'avg_sentence_length': word_count / sentence_count if sentence_count else 0,
            'vocabulary_richness': vocabulary_richness,
            'top_words': top_words
        }

    def analyze_file(self, csv_path):
        """Analyze a single anomaly CSV file"""
        if not csv_path or not os.path.exists(csv_path):
            logging.error(f"CSV file not found: {csv_path}")
            return False
        csv_filename = os.path.basename(csv_path)
        self.current_file = csv_filename
        logging.info(f"Analyzing anomaly file: {csv_filename}")
        self.responses = []
        self.metrics_list = []
        groups = self.prepare_data(csv_path)
        if not groups:
            logging.warning(f"No valid connection groups found in {csv_filename}")
            return False
        for i, group in enumerate(groups, start=1):
            prompt = self.generate_prompt(group, csv_filename)
            logging.info(f"Generating analysis for group {i}/{len(groups)}")
            response, elapsed_time, chunk_times = self.get_ollama_response(prompt)
            metrics = self.calculate_metrics(response, elapsed_time, chunk_times)
            self.responses.append(f"===== Connection Group {i} Analysis =====\n{response}")
            self.metrics_list.append(metrics)

        # Save the main analysis results
        analysis_path = self.save_analysis_results(csv_filename)
        self.track_analyzed_file(csv_filename)
        return True

    def save_analysis_results(self, csv_filename):
        """Save the analysis results for a file"""
        base_name = os.path.splitext(csv_filename)[0]
        output_filename = f"{base_name}_analysis_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
        output_path = os.path.join(self.output_dir, output_filename)
        combined_response = "\n\n".join(self.responses)
        consolidated_metrics = self.consolidate_metrics()
        header = f"""
===========================================================
ANOMALY ANALYSIS RESULTS
===========================================================
Source File: {csv_filename}
Model Used: {self.model_name}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
===========================================================

"""
        try:
            with open(output_path, "w") as output_file:
                output_file.write(header + consolidated_metrics + "\n\n" + combined_response)
            logging.info(f"Analysis saved to: {output_path}")
            return output_path
        except Exception as e:
            logging.error(f"Error saving analysis results: {e}")
            return None

    def track_analyzed_file(self, csv_filename):
        """Add the file to the list of analyzed files"""
        tracker_path = os.path.join(self.output_dir, "analyzed_files.txt")
        try:
            with open(tracker_path, "a") as tracker:
                tracker.write(f"{csv_filename}\n")
            self.analyzed_files.append(csv_filename)
        except Exception as e:
            logging.error(f"Error tracking analyzed file: {e}")

    def consolidate_metrics(self):
        """Consolidate metrics across all analyzed groups"""
        if not self.metrics_list:
            return "No metrics available."
        total_elapsed_time = sum(m['elapsed_time'] for m in self.metrics_list)
        avg_response_rate = sum(m['response_rate'] for m in self.metrics_list) / len(self.metrics_list) if self.metrics_list else 0
        total_word_count = sum(m['word_count'] for m in self.metrics_list)
        total_char_count = sum(m['char_count'] for m in self.metrics_list)
        total_sentence_count = sum(m['sentence_count'] for m in self.metrics_list)
        avg_word_length = total_char_count / total_word_count if total_word_count > 0 else 0
        avg_sentence_length = total_word_count / total_sentence_count if total_sentence_count > 0 else 0
        avg_vocabulary_richness = sum(m['vocabulary_richness'] for m in self.metrics_list) / len(self.metrics_list) if self.metrics_list else 0
        combined_word_freq = Counter()
        for metrics in self.metrics_list:
             # Ensure top_words is treated as a list of tuples
             if isinstance(metrics.get('top_words'), list):
                 combined_word_freq.update(dict(metrics['top_words']))
        top_5_words_combined = combined_word_freq.most_common(5)
        return f"""
ANALYSIS METRICS:
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

    def run_analysis(self, mode='latest'):
        """Run analysis on anomaly files based on mode"""
        result = False
        if mode == 'latest':
            latest_file = self.find_latest_anomaly_file()
            if latest_file:
                result = self.analyze_file(latest_file)
            else:
                logging.error("No anomaly files found to analyze.")
        elif mode == 'all':
            unanalyzed_files = self.find_unanalyzed_files()
            if unanalyzed_files:
                for file in unanalyzed_files:
                    file_result = self.analyze_file(file)
                    result = result or file_result # Keep track if any file was successfully analyzed
                    time.sleep(1)
            else:
                logging.info("No new anomaly files to analyze.")
        elif mode == 'file' and self.specific_file:
            if os.path.exists(self.specific_file):
                result = self.analyze_file(self.specific_file)
            else:
                logging.error(f"Specified file not found: {self.specific_file}")
        else:
            logging.error(f"Invalid analysis mode: {mode}")
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze network anomaly CSV files using Ollama models")
    parser.add_argument("-m", "--model", default="dolphin-llama3:8b",
                        help="Ollama model to use for analysis (default: dolphin-llama3:8b)")
    parser.add_argument("-d", "--anomaly-dir",
                        help="Directory containing anomaly CSV files (default: ../detector/anomaly_logs)")
    parser.add_argument("-o", "--output-dir",
                        help="Directory to save analysis results (default: ./analysis_results)")
    parser.add_argument("-f", "--file",
                        help="Specific anomaly CSV file to analyze")
    parser.add_argument("--mode", choices=["latest", "all", "file"], default="latest",
                        help="Analysis mode: latest (default), all unanalyzed files, or specific file")

    args = parser.parse_args()

    analyzer = AnomalyOllamaAnalyzer(
        model_name=args.model,
        anomaly_dir=args.anomaly_dir,
        output_dir=args.output_dir,
        specific_file=args.file
    )

    if args.file and args.mode != "file":
        args.mode = "file"
        logging.info("Setting mode to 'file' since a specific file was provided")

    analyzer.run_analysis(mode=args.mode)
